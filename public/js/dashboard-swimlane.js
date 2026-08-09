// Timeline Swimlane (#415 tier 3) — the canvas chart: assets/severity/tactics on Y, time on X.
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE. Seven mutable bindings (swLanes, the view window, the drag
// and rubber-band scratch) would otherwise join the shared global lexical environment of a classic
// script: invisible to Object.keys, but writable by name from any script that loads later. Only
// the six names assigned to window at the bottom are public; everything else is closed over.
//
// WHY initSwimlane() IS A FUNCTION AND NOT A SELF-INVOKING IIFE. This file is a <script src> in
// <head>, and #sec-swimlane's markup does not exist yet when it runs — document.getElementById
// ("swimlaneCanvas") would return null, every listener would attach to nothing, and the feature
// would be silently absent with no error anywhere. So the wiring stays a function and the page
// calls it at the point in the inline script where the old IIFE used to sit, guarded, because a
// missing file must cost the chart and not the rest of the page.
//
// THE SIX PUBLISHED NAMES are the ones the inline script still reaches for: loadSwimlane (the
// lazy section-loader table), scheduleSwimlaneReload (the scope fan-out and the WebSocket state
// branch), swRenderCanvas and swSelToolbar (the timeline's selection code and the re-theme pass),
// swReflectSelection (the table -> chart half of the bidirectional selection), and initSwimlane.
//
// swLocateInTable DID NOT COME WITH THIS FEATURE. Its name says swimlane; its body scrolls and
// flashes a row in #forensicTimeline .ev-row and touches no swimlane state. Its only two callers
// are inside jumpToEvent, which stays in the page. Moving it would mean exporting it straight
// back. swCanvasXY is likewise not ours: it lives in js/dashboard-values.js.

(function () {
    // ── Timeline Swimlane ───────────────────────────────────────────────────────────────
    // Canvas-based swimlane chart: assets/severity/tactics on Y-axis, time on X-axis.
    // Data comes from GET /cases/:id/swimlane?groupBy=... (server applies scope+FP filtering).
    // View window (swViewStartMs…swViewEndMs) drives all rendering; zoom/pan mutate it.

    const SW_LANE_H = 36;    // px per lane row
    const SW_AXIS_H = 26;    // px for the time-axis strip
    const SW_DOT_R  = 5;     // default event dot radius (px)
    // Severity/label → theme token. The swimlane is a <canvas>, which can't read CSS vars, so these
    // are resolved to concrete colors at draw time via themeColor() and the canvas is redrawn on a
    // theme switch (rethemeCanvases()).
    const SW_SEV_TOKEN = { Critical:"--sev-critical", High:"--sev-high", Medium:"--sev-medium", Low:"--sev-low", Info:"--accent" };
    const SW_LABEL_TOKEN = { host:"--accent", account:"--text-primary", severity:"--text-primary", tactic:"--text-primary", unassigned:"--text-faint" };

    // View window: swViewStartMs…swViewEndMs drive all rendering; zoom/pan mutate it.
    let swLanes = [];          // [{id,label,type,events:[…]}] from server
    let swDataMinMs = 0, swDataMaxMs = 0;
    let swViewStartMs = 0, swViewEndMs = 0;
    let swDrag = false, swDragMoved = false, swDragStartX = 0, swDragViewStart = 0;
    let swHoverEvId = null, swSelEvId = null, swTimer = null;
    let swRubber = null;       // {x0,y0,x1,y1} canvas-px rect while Shift-dragging a selection box
    let swTimeBrush = null;    // {x0,x1} canvas-px while dragging the time axis to filter the timeline
    // Multi-select reuses the timeline table's shared `selectedEvents` Set (declared above), so
    // selection is bidirectional: dots ringed here ⇄ rows checked there ⇄ the bulk-action bars.

    function swFitView() { swViewStartMs = swDataMinMs; swViewEndMs = swDataMaxMs; }

    // Keep the panel subtitle's "Y-axis: …" in sync with the Group by selection.
    const SW_AXIS_LABEL = { asset: "assets", severity: "severity", tactic: "tactic" };
    function swUpdateSubtitle() {
      const sub = document.getElementById("swimlaneSub");
      if (!sub) return;
      const g = document.getElementById("swimlaneGroupBy").value || "asset";
      sub.textContent = `visual chart — Y-axis: ${SW_AXIS_LABEL[g] || g} · X-axis: time · color: severity (derived, no AI)`;
    }

    function swZoomRatio() {
      const d = swDataMaxMs - swDataMinMs, v = swViewEndMs - swViewStartMs;
      return (!d || !v) ? 1 : d / v;
    }

    function swTsToX(ms, W) {
      const span = swViewEndMs - swViewStartMs;
      return span ? ((ms - swViewStartMs) / span) * W : W / 2;
    }

    function swXToTs(x, W) {
      const span = swViewEndMs - swViewStartMs;
      return swViewStartMs + (x / W) * span;
    }

    function loadSwimlane(caseId) {
      const groupBy = document.getElementById("swimlaneGroupBy").value || "asset";
      swUpdateSubtitle();
      fetch(`/cases/${caseId}/swimlane?groupBy=${encodeURIComponent(groupBy)}`)
        .then(r => r.json()).then(d => {
          swLanes = Array.isArray(d.lanes) ? d.lanes : [];
          swDataMinMs = d.minTime ? Date.parse(d.minTime) : 0;
          swDataMaxMs = d.maxTime ? Date.parse(d.maxTime) : 0;
          if (swDataMinMs === swDataMaxMs) { swDataMinMs -= 60000; swDataMaxMs += 60000; }
          swFitView(); swSelEvId = null;
          const det = document.getElementById("swimlaneDetail");
          if (det) det.hidden = true;
          swRenderLabels(); swRenderCanvas(); swUpdateZoomLabel(); swSelToolbar();
        }).catch(() => {});
    }

    function scheduleSwimlaneReload() {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      clearTimeout(swTimer);
      swTimer = setTimeout(() => loadSwimlane(caseId), 800);
    }

    function swRenderLabels() {
      const el = document.getElementById("swimlaneLabels");
      if (!el) return;
      if (!swLanes.length) { el.innerHTML = ""; return; }
      el.innerHTML = swLanes.map(l =>
        `<div class="swimlane-label ${esc(l.type)}" data-safe-style="height:${SW_LANE_H}px" title="${escAttr(l.label)}">${esc(l.label)}</div>`
      ).join("") + `<div data-safe-style="height:${SW_AXIS_H}px"></div>`;
    }

    function swRenderCanvas() {
      const canvas = document.getElementById("swimlaneCanvas");
      if (!canvas) return;
      const W = Math.max(100, canvas.parentElement.clientWidth || 600);
      const H = swLanes.length * SW_LANE_H + SW_AXIS_H;
      canvas.width = W; canvas.height = H; canvas.style.height = H + "px";
      const ctx = canvas.getContext("2d");
      ctx.clearRect(0, 0, W, H);
      if (!swLanes.length) {
        ctx.fillStyle = themeColor("--text-faint"); ctx.font = "12px system-ui,sans-serif"; ctx.textAlign = "center";
        ctx.fillText("No dated events to display. Load a case with a forensic timeline.", W / 2, 24);
        return;
      }
      // Lane stripes
      swLanes.forEach((_, i) => {
        ctx.fillStyle = i % 2 === 0 ? themeColor("--bg-primary") : themeColor("--bg-primary");
        ctx.fillRect(0, i * SW_LANE_H, W, SW_LANE_H);
        ctx.strokeStyle = themeColor("--border-subtle"); ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(0, (i+1)*SW_LANE_H-.5); ctx.lineTo(W, (i+1)*SW_LANE_H-.5); ctx.stroke();
      });
      // Time axis
      const axY = swLanes.length * SW_LANE_H;
      ctx.fillStyle = themeColor("--bg-primary"); ctx.fillRect(0, axY, W, SW_AXIS_H);
      ctx.strokeStyle = themeColor("--border-color"); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(0, axY+.5); ctx.lineTo(W, axY+.5); ctx.stroke();
      // Tick marks
      const visSpan = swViewEndMs - swViewStartMs;
      const rawI = visSpan / Math.max(3, Math.floor(W/90));
      const TICK_STEPS = [1000,5000,10000,30000,60000,120000,300000,600000,900000,1800000,
                          3600000,6*3600000,12*3600000,24*3600000,2*86400000,7*86400000];
      const tickI = TICK_STEPS.find(v => v >= rawI) || TICK_STEPS[TICK_STEPS.length-1];
      ctx.fillStyle = themeColor("--text-muted"); ctx.font = "10px system-ui,sans-serif"; ctx.textAlign = "center";
      for (let t = Math.ceil(swViewStartMs/tickI)*tickI; t <= swViewEndMs; t += tickI) {
        const x = swTsToX(t, W);
        ctx.strokeStyle = themeColor("--bg-tertiary"); ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(x+.5,0); ctx.lineTo(x+.5,axY); ctx.stroke();
        ctx.strokeStyle = themeColor("--border-strong");
        ctx.beginPath(); ctx.moveTo(x+.5,axY); ctx.lineTo(x+.5,axY+5); ctx.stroke();
        const nd = new Date(t);
        const lbl = tickI >= 86400000 ? nd.toISOString().slice(0,10)
                  : tickI >= 3600000  ? nd.toISOString().slice(11,16)+"Z"
                  :                     nd.toISOString().slice(11,19)+"Z";
        ctx.fillText(lbl, x, axY+18);
      }
      // Event dots
      swLanes.forEach((lane, i) => {
        const cy = i*SW_LANE_H + SW_LANE_H/2;
        for (const e of lane.events) {
          const ms = Date.parse(e.timestamp); if (Number.isNaN(ms)) continue;
          const x = swTsToX(ms, W); if (x < -SW_DOT_R || x > W+SW_DOT_R) continue;
          const r = e.count && e.count > 5 ? SW_DOT_R+2 : SW_DOT_R;
          ctx.beginPath(); ctx.arc(x, cy, r, 0, 2*Math.PI);
          ctx.fillStyle = e.id === swSelEvId ? themeColor("--text-bright") : themeColor(SW_SEV_TOKEN[e.severity]||"--accent");
          ctx.fill();
          if (e.id === swHoverEvId || e.id === swSelEvId) {
            ctx.strokeStyle = themeColor("--text-bright"); ctx.lineWidth = 1.5; ctx.stroke();
          }
          // Multi-select ring (events chosen for a batch action; bidirectional with the table).
          if (DfirSelection.events.has(e.id)) {
            ctx.beginPath(); ctx.arc(x, cy, r+3, 0, 2*Math.PI);
            ctx.strokeStyle = themeColor("--accent"); ctx.lineWidth = 2; ctx.stroke();
          }
        }
      });
      // Rubber-band selection rectangle (while Shift-dragging)
      if (swRubber) {
        const rx = Math.min(swRubber.x0, swRubber.x1), ry = Math.min(swRubber.y0, swRubber.y1);
        const rw = Math.abs(swRubber.x1 - swRubber.x0), rh = Math.abs(swRubber.y1 - swRubber.y0);
        ctx.fillStyle = "rgba(106,169,255,0.15)"; ctx.fillRect(rx, ry, rw, rh);
        ctx.strokeStyle = themeColor("--accent"); ctx.lineWidth = 1; ctx.strokeRect(rx+.5, ry+.5, rw, rh);
      }
      // Time-brush overlay (while dragging the time axis)
      if (swTimeBrush) {
        const bx0 = Math.min(swTimeBrush.x0, swTimeBrush.x1);
        const bx1 = Math.max(swTimeBrush.x0, swTimeBrush.x1);
        ctx.fillStyle = "rgba(255,217,59,0.12)"; ctx.fillRect(bx0, 0, bx1 - bx0, axY);
        ctx.strokeStyle = "#ffd93b"; ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.moveTo(bx0 + .5, 0); ctx.lineTo(bx0 + .5, axY); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(bx1 + .5, 0); ctx.lineTo(bx1 + .5, axY); ctx.stroke();
      }
      // The canvas above reaches no screen reader; see js/a11y/describe-as-table.js (#386).
      if (window.DfirChartTable) window.DfirChartTable.renderSwimlaneTable(swLanes);
    }

    function swHitTest(canvas, cx, cy) {
      const li = Math.floor(cy / SW_LANE_H);
      if (li < 0 || li >= swLanes.length) return null;
      const lane = swLanes[li], cy0 = li*SW_LANE_H + SW_LANE_H/2;
      let best = null, bd = SW_DOT_R*3;
      for (const e of lane.events) {
        const ms = Date.parse(e.timestamp); if (Number.isNaN(ms)) continue;
        const x = swTsToX(ms, canvas.width);
        const d = Math.sqrt((cx-x)**2 + (cy-cy0)**2);
        if (d < bd) { best = e; bd = d; }
      }
      return best;
    }

    function swShowDetail(evObj) {
      const det = document.getElementById("swimlaneDetail");
      if (!det) return;
      if (!evObj) { det.hidden = true; return; }
      const desc = String(evObj.description||"").replace(/\s*\[corroborated by \d+ sources?:[^\]]*\]\s*$/i,"");
      det.hidden = false;
      det.innerHTML =
        `<div class="swimlane-detail-header">` +
        `<span class="sev-${esc(evObj.severity)}">[${esc(evObj.severity)}]</span> ` +
        `<span data-safe-style="color:var(--text-muted)">${esc(evObj.timestamp||"")}</span>` +
        (evObj.count&&evObj.count>1 ? ` <span data-safe-style="color:var(--text-muted)">(×${evObj.count})</span>` : "") +
        `</div><div>${esc(desc)}</div>` +
        ((evObj.mitreTechniques||[]).length ? `<div>MITRE: ${mitreLinks(evObj.mitreTechniques)}</div>` : "") +
        ((evObj.sources||[]).length ? `<div data-safe-style="color:var(--text-muted)">Sources: ${esc(evObj.sources.join(", "))}</div>` : "") +
        ((evObj.relatedFindingIds||[]).length
          ? `<div data-safe-style="color:var(--text-muted)">Related: ${evObj.relatedFindingIds.map(f=>`<span data-safe-style="color:var(--accent)">${esc(f)}</span>`).join(", ")}</div>`
          : "");
    }

    function swUpdateZoomLabel() {
      const el = document.getElementById("swimlaneZoomLevel");
      if (el) el.textContent = Math.round(swZoomRatio() * 100) + "%";
    }

    // ---- Selection (bidirectional with the timeline table via the shared `selectedEvents`) ----
    function swSelToolbar() {
      const bar = document.getElementById("swimlaneSelBar");
      if (!bar) return;
      const n = DfirSelection.events.count();
      if (n > 0) {
        bar.classList.add("active");
        document.getElementById("swimlaneSelCount").textContent = `${n} event${n !== 1 ? "s" : ""} selected`;
      } else {
        bar.classList.remove("active");
      }
    }
    // Selection changed FROM the swimlane → refresh both bulk bars, the table, and the chart.
    function swSelectionChanged() {
      updateBulkBar(); swSelToolbar();
      renderTimelineEvents(DfirState.lastFt());   // table rows reflect the new selection
      swRenderCanvas();               // dots get / lose their ring
    }
    // Selection changed FROM the table → just refresh the swimlane chrome (table already updated).
    function swReflectSelection() { swSelToolbar(); swRenderCanvas(); }

    // Finish a Shift-drag: a tiny box is a single toggle; a real box adds every enclosed dot.
    function swFinishRubber() {
      const canvas = document.getElementById("swimlaneCanvas");
      if (!canvas || !swRubber) return;
      const x0 = Math.min(swRubber.x0, swRubber.x1), x1 = Math.max(swRubber.x0, swRubber.x1);
      const y0 = Math.min(swRubber.y0, swRubber.y1), y1 = Math.max(swRubber.y0, swRubber.y1);
      if ((x1 - x0) < 4 && (y1 - y0) < 4) {
        const hit = swHitTest(canvas, swRubber.x1, swRubber.y1);
        if (hit) DfirSelection.events.toggle(hit.id);
      } else {
        const hits = [];   // collected first, committed once — see js/dashboard-selection.js
        swLanes.forEach((lane, i) => {
          const cy = i * SW_LANE_H + SW_LANE_H / 2;
          if (cy < y0 || cy > y1) return;
          for (const e of lane.events) {
            const ms = Date.parse(e.timestamp); if (Number.isNaN(ms)) continue;
            const x = swTsToX(ms, canvas.width);
            if (x >= x0 && x <= x1) hits.push(e.id);
          }
        });
        DfirSelection.events.addAll(hits);
      }
      swSelectionChanged();
    }

    // Set the investigation scope window to the currently visible time range, then apply it.
    function swScopeToView() {
      if (!swViewStartMs || !swViewEndMs) return;
      document.getElementById("scopeStart").value = isoToUtcInput(new Date(swViewStartMs).toISOString());
      document.getElementById("scopeEnd").value = isoToUtcInput(new Date(swViewEndMs).toISOString());
      applyScope();
    }

    // Download the swimlane as a PNG — composes the lane labels + the chart canvas into one image
    // (the on-screen labels are separate HTML, so a bare canvas export would lose them).
    function swExportPng() {
      const canvas = document.getElementById("swimlaneCanvas");
      if (!canvas || !swLanes.length) return;
      const labelW = 160;
      const off = document.createElement("canvas");
      off.width = labelW + canvas.width;
      off.height = canvas.height;
      const o = off.getContext("2d");
      o.fillStyle = themeColor("--bg-primary"); o.fillRect(0, 0, off.width, off.height);
      o.textBaseline = "middle"; o.font = "12px system-ui,sans-serif";
      swLanes.forEach((l, i) => {
        o.fillStyle = themeColor(SW_LABEL_TOKEN[l.type] || "--text-primary");
        const name = l.label.length > 22 ? l.label.slice(0, 21) + "…" : l.label;
        o.fillText(name, 8, i * SW_LANE_H + SW_LANE_H / 2);
      });
      o.strokeStyle = themeColor("--border-color"); o.beginPath(); o.moveTo(labelW - .5, 0); o.lineTo(labelW - .5, canvas.height); o.stroke();
      o.drawImage(canvas, labelW, 0);
      const caseId = document.getElementById("caseId").value.trim() || "case";
      const a = document.createElement("a");
      a.href = off.toDataURL("image/png");
      a.download = `swimlane-${caseId}.png`;
      document.body.appendChild(a); a.click(); a.remove();
    }

    // Wiring. Called by the page where the old setupSwimlane IIFE sat, once the markup exists.
    // The canvas and tooltip THIS FEATURE IS CURRENTLY DRIVING. The window-level drag handlers below
    // outlive any one panel, so they must read these rather than close over whichever elements
    // existed the first time they were registered — after a re-render those are detached, and a
    // handler quietly styling a detached node is the same silent failure by another route.
    let swCanvas = null;
    let swTooltip = null;
    // Which canvas element is wired, and whether the document/window handlers are up. Two separate
    // questions: the panel's own controls belong to the element and must be re-wired when the markup
    // is rebuilt, while the global handlers belong to the page and must not stack (#496).
    let swWiredCanvas = null;
    const swGlobalsWired = new Set();
    function swOnceGlobal(target, type, fn) {
      const key = (target === window ? "window:" : "document:") + type;
      if (swGlobalsWired.has(key)) return;
      swGlobalsWired.add(key);
      target.addEventListener(type, fn);
    }
    function initSwimlane() {
      const canvas = document.getElementById("swimlaneCanvas");
      const tooltip = document.getElementById("swimlaneTooltip");
      if (!canvas) return;
      swCanvas = canvas;
      swTooltip = tooltip;
      // KEYED ON THE ELEMENT, not a boolean. A module-wide one-shot makes a repeat call safe and a
      // re-render fatal: rebuilt markup means a NEW canvas, and a flag would refuse to wire it,
      // leaving the panel silently dead rather than merely double-wired. Asked of the element, a
      // second call on the same panel does nothing and a rebuilt panel is wired afresh.
      if (swWiredCanvas === canvas) return;
      swWiredCanvas = canvas;

      // Zoom via mouse wheel — pin the time under the cursor
      canvas.addEventListener("wheel", function(e) {
        e.preventDefault();
        const rect = canvas.getBoundingClientRect();
        const cx = (e.clientX - rect.left) * (canvas.width / rect.width);
        const pivotMs = swXToTs(cx, canvas.width);
        const factor = e.deltaY < 0 ? 1.3 : 1/1.3;
        const curSpan = swViewEndMs - swViewStartMs;
        const dataSpan = swDataMaxMs - swDataMinMs;
        const newSpan = Math.max(1000, Math.min(dataSpan, curSpan / factor));
        const frac = cx / canvas.width;
        let ns = pivotMs - frac * newSpan;
        let ne = ns + newSpan;
        if (ns < swDataMinMs) { ns = swDataMinMs; ne = ns + newSpan; }
        if (ne > swDataMaxMs) { ne = swDataMaxMs; ns = ne - newSpan; }
        swViewStartMs = Math.max(swDataMinMs, ns);
        swViewEndMs   = Math.min(swDataMaxMs, ne);
        swUpdateZoomLabel(); swRenderCanvas();
      }, { passive: false });

      // Pan via drag — OR Shift-drag rubber-band selection — OR drag the time axis to filter the timeline.
      canvas.addEventListener("mousedown", function(e) {
        const p = swCanvasXY(e, canvas);
        const axY = swLanes.length * SW_LANE_H;
        if (!e.shiftKey && p.y >= axY) {
          swTimeBrush = { x0: p.x, x1: p.x };
          swDrag = false; e.preventDefault(); return;
        }
        if (e.shiftKey) {
          swRubber = { x0: p.x, y0: p.y, x1: p.x, y1: p.y };
          swDrag = false; e.preventDefault(); return;
        }
        swDrag = true; swDragMoved = false;
        swDragStartX = e.clientX; swDragViewStart = swViewStartMs;
        canvas.style.cursor = "grabbing";
      });
      swOnceGlobal(window, "mousemove", function(e) {
        if (swTimeBrush) {
          const p = swCanvasXY(e, swCanvas);
          swTimeBrush.x1 = Math.max(0, Math.min(swCanvas.width, p.x));
          swRenderCanvas(); return;
        }
        if (swRubber) {
          const p = swCanvasXY(e, swCanvas);
          swRubber.x1 = Math.max(0, Math.min(swCanvas.width, p.x));
          swRubber.y1 = Math.max(0, Math.min(swCanvas.height, p.y));
          swRenderCanvas(); return;
        }
        if (swDrag) {
          const dx = e.clientX - swDragStartX;
          if (Math.abs(dx) > 3) swDragMoved = true;
          const span = swViewEndMs - swViewStartMs;
          const dtMs = -(dx / (swCanvas.width||600)) * span;
          let ns = swDragViewStart + dtMs;
          if (ns < swDataMinMs) ns = swDataMinMs;
          if (ns + span > swDataMaxMs) ns = swDataMaxMs - span;
          swViewStartMs = Math.max(swDataMinMs, ns);
          swViewEndMs = swViewStartMs + span;
          swRenderCanvas(); return;
        }
        const rect = swCanvas.getBoundingClientRect();
        const cx = (e.clientX - rect.left) * (swCanvas.width / rect.width);
        const cy = (e.clientY - rect.top) * (swCanvas.height / rect.height);
        if (swLanes.length && cy < swLanes.length * SW_LANE_H) {
          const hit = swHitTest(swCanvas, cx, cy);
          if (hit) {
            const d = String(hit.description||"").replace(/\s*\[corroborated by \d+ sources?:[^\]]*\]\s*$/i,"").slice(0,120);
            swTooltip.textContent = `[${hit.severity}] ${hit.timestamp}` +
              (hit.count&&hit.count>1 ? ` (×${hit.count})` : "") + `\n${d}`;
            swTooltip.style.display = "block";
            swTooltip.style.left = (e.clientX+14)+"px";
            swTooltip.style.top  = (e.clientY-10)+"px";
            if (swHoverEvId !== hit.id) { swHoverEvId = hit.id; swRenderCanvas(); }
          } else {
            swTooltip.style.display = "none";
            if (swHoverEvId) { swHoverEvId = null; swRenderCanvas(); }
          }
        } else {
          swTooltip.style.display = "none";
          if (swHoverEvId) { swHoverEvId = null; swRenderCanvas(); }
        }
      });
      swOnceGlobal(window, "mouseup", function() {
        if (swTimeBrush) {
          const tb = swTimeBrush; swTimeBrush = null;
          const x0 = Math.min(tb.x0, tb.x1), x1 = Math.max(tb.x0, tb.x1);
          if (x1 - x0 > 4) {
            const ms0 = swXToTs(x0, swCanvas.width), ms1 = swXToTs(x1, swCanvas.width);
            DfirTimelineView.setTimeWindow(new Date(ms0).toISOString(), new Date(ms1).toISOString());
            const sec = document.getElementById("sec-timeline");
            if (sec && sec.classList.contains("collapsed")) sec.classList.remove("collapsed");
          }
          swRenderCanvas(); return;
        }
        if (swRubber) { swFinishRubber(); swRubber = null; swRenderCanvas(); return; }
        if (swDrag) { swDrag = false; swCanvas.style.cursor = "crosshair"; }
      });
      canvas.addEventListener("mouseleave", function() {
        tooltip.style.display = "none";
        if (swHoverEvId) { swHoverEvId = null; swRenderCanvas(); }
      });

      // Click to select event (ignored when the drag moved the view; Shift-clicks are selection).
      canvas.addEventListener("click", function(e) {
        if (swDragMoved) { swDragMoved = false; return; }
        if (e.shiftKey) return;   // handled on mouseup as a rubber-band toggle
        const rect = canvas.getBoundingClientRect();
        const cx = (e.clientX - rect.left) * (canvas.width / rect.width);
        const cy = (e.clientY - rect.top) * (canvas.height / rect.height);
        const hit = swHitTest(canvas, cx, cy);
        swSelEvId = hit ? hit.id : null;
        swShowDetail(hit || null);
        swRenderCanvas();
        if (hit) jumpToEvent(hit.id);   // expand/page/unfilter the timeline as needed, then flash the row
      });

      document.getElementById("swimlaneGroupBy").addEventListener("change", function() {
        const caseId = document.getElementById("caseId").value.trim();
        if (caseId) loadSwimlane(caseId);
      });
      document.getElementById("swimlaneZoomIn").addEventListener("click", function() {
        const c = (swViewStartMs+swViewEndMs)/2, h = (swViewEndMs-swViewStartMs)/2/1.5;
        swViewStartMs = Math.max(swDataMinMs,c-h); swViewEndMs = Math.min(swDataMaxMs,c+h);
        swUpdateZoomLabel(); swRenderCanvas();
      });
      document.getElementById("swimlaneZoomOut").addEventListener("click", function() {
        const c = (swViewStartMs+swViewEndMs)/2;
        const h = Math.min((swDataMaxMs-swDataMinMs)/2, (swViewEndMs-swViewStartMs)/2*1.5);
        swViewStartMs = Math.max(swDataMinMs,c-h); swViewEndMs = Math.min(swDataMaxMs,c+h);
        swUpdateZoomLabel(); swRenderCanvas();
      });
      document.getElementById("swimlaneZoomFit").addEventListener("click", function() {
        swFitView(); swUpdateZoomLabel(); swRenderCanvas();
      });
      // Prefer the native Fullscreen API; fall back to a CSS "maximize" (fixed, fills the
      // viewport) when it's unavailable or rejected — e.g. served over a plain-HTTP LAN IP,
      // which isn't a secure context. Only the toggle is affected, never the chart itself.
      function swMaximizeCss(on) {
        document.getElementById("sec-swimlane").classList.toggle("swimlane-maximized", on);
        setTimeout(swRenderCanvas, 60);
      }
      document.getElementById("swimlaneFullscreen").addEventListener("click", function() {
        const sec = document.getElementById("sec-swimlane");
        if (sec.classList.contains("swimlane-maximized")) { swMaximizeCss(false); return; }
        if (document.fullscreenElement === sec) { document.exitFullscreen(); return; }
        if (sec.requestFullscreen) sec.requestFullscreen().catch(() => swMaximizeCss(true));
        else swMaximizeCss(true);
      });
      // Esc exits the CSS fallback (the native API already handles its own Esc).
      swOnceGlobal(document, "keydown", function(e) {
        if (e.key === "Escape" &&
            document.getElementById("sec-swimlane").classList.contains("swimlane-maximized")) {
          swMaximizeCss(false);
        }
      });
      // Re-render at the new viewport width when the swimlane enters/exits native fullscreen.
      swOnceGlobal(document, "fullscreenchange", function() {
        if (document.fullscreenElement && document.fullscreenElement.id !== "sec-swimlane") return;
        setTimeout(swRenderCanvas, 60);   // wait for the fullscreen relayout before measuring
      });
      document.getElementById("swimlaneScopeView").addEventListener("click", swScopeToView);
      document.getElementById("swimlanePng").addEventListener("click", swExportPng);
      document.getElementById("swimlaneSelFp").addEventListener("click", function() {
        if (DfirSelection.events.count()) bulkMarkFalsePositive();   // shared with the table's bulk bar
      });
      document.getElementById("swimlaneSelClear").addEventListener("click", function() {
        DfirSelection.events.clear(); swSelectionChanged();
      });
      if (typeof ResizeObserver !== "undefined") {
        new ResizeObserver(() => swRenderCanvas()).observe(document.getElementById("swimlaneWrap"));
      }
    }
  // ── published surface ─────────────────────────────────────────────────────────────────
  // Everything not on this list is unreachable from the page, which is the point of the wrapper.
  window.loadSwimlane = loadSwimlane;
  window.scheduleSwimlaneReload = scheduleSwimlaneReload;
  window.swRenderCanvas = swRenderCanvas;
  window.swSelToolbar = swSelToolbar;
  window.swReflectSelection = swReflectSelection;
  window.initSwimlane = initSwimlane;
})();
