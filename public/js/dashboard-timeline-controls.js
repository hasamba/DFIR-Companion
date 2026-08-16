// Forensic timeline controls — the source/origin/host filter menus, the row-click delegate, the
// confidence filter and the collection-deploy handler. Extracted from dashboard.html (#415 tier 3).
//
// My own dispatch rule flagged this block as core machinery because it declares nothing and only
// listens. I argued in the previous commit that the flag is over-broad, and this module is me
// acting on that argument rather than leaving it as a note.
//
// The distinction the rule misses: the page's 447-line wiring block routes clicks for EVERY
// feature, so losing it leaves nothing on the page clickable. This block is ONE feature's controls
// calling into renderTimelineEvents next door. A missing module costs the timeline's filter menus
// — a decoration loss, which is the failure the facade is designed around.
//
// Every statement here runs at load, so the whole block is the initializer and there is no module
// body at all. renderTimelineEvents stays in the page: it is spine, and these call it.
(function () {
  "use strict";

  function initTimelineControls() {
    // Source/tool filter dropdown (#131 follow-up). The button + menu are persistent in the DOM;
    // the menu's checkbox list is rebuilt by renderSourceFilter, so all handlers are delegated.
    (function () {
      const wrap = document.getElementById("srcLegendWrap");
      const btn = document.getElementById("srcFilterBtn");
      const menu = document.getElementById("srcFilterMenu");
      if (!wrap || !btn || !menu) return;
      btn.addEventListener("click", () => {
        menu.hidden = !menu.hidden;
      });
      menu.addEventListener("change", (e) => {
        if (!e.target.classList.contains("src-filter")) return;
        DfirFacets.sources.toggle(e.target.value, !e.target.checked);
        renderTimelineEvents(DfirState.lastFt());
      });
      menu.addEventListener("click", (e) => {
        if (e.target.dataset.srcAll) {
          DfirFacets.sources.showAll();
          renderTimelineEvents(DfirState.lastFt());
        } else if (e.target.dataset.srcNone) {
          DfirFacets.sources.hideAll(sourceFacets(DfirState.lastFt()));
          renderTimelineEvents(DfirState.lastFt());
        }
      });
      // Close the menu when clicking outside it (clicks inside #srcLegendWrap are stopped at the wrap).
      document.addEventListener("click", (e) => {
        if (!menu.hidden && !wrap.contains(e.target)) menu.hidden = true;
      });
    })();

    // Forensic origin filter dropdown — mirrors the source filter exactly, scoped to its own menu
    // element. Origin is one level more specific than Source (the artifact, not just the tool) —
    // matches the super-timeline's Origins filter.
    (function () {
      const wrap = document.getElementById("originLegendWrap");
      const btn = document.getElementById("originFilterBtn");
      const menu = document.getElementById("originFilterMenu");
      if (!wrap || !btn || !menu) return;
      btn.addEventListener("click", () => {
        menu.hidden = !menu.hidden;
      });
      menu.addEventListener("change", (e) => {
        if (!e.target.classList.contains("origin-filter")) return;
        DfirFacets.origins.toggle(e.target.value, !e.target.checked);
        renderTimelineEvents(DfirState.lastFt());
      });
      menu.addEventListener("click", (e) => {
        if (e.target.dataset.originAll) {
          DfirFacets.origins.showAll();
          renderTimelineEvents(DfirState.lastFt());
        } else if (e.target.dataset.originNone) {
          DfirFacets.origins.hideAll(originFacets(DfirState.lastFt()));
          renderTimelineEvents(DfirState.lastFt());
        }
      });
      document.addEventListener("click", (e) => {
        if (!menu.hidden && !wrap.contains(e.target)) menu.hidden = true;
      });
    })();

    // Forensic host filter dropdown — mirrors the source filter exactly, scoped to its own menu element.
    (function () {
      const wrap = document.getElementById("hostLegendWrap");
      const btn = document.getElementById("hostFilterBtn");
      const menu = document.getElementById("hostFilterMenu");
      if (!wrap || !btn || !menu) return;
      btn.addEventListener("click", () => {
        menu.hidden = !menu.hidden;
      });
      menu.addEventListener("change", (e) => {
        if (!e.target.classList.contains("host-filter")) return;
        DfirFacets.hosts.toggle(e.target.value, !e.target.checked);
        renderTimelineEvents(DfirState.lastFt());
      });
      menu.addEventListener("click", (e) => {
        if (e.target.dataset.hostAll) {
          DfirFacets.hosts.showAll();
          renderTimelineEvents(DfirState.lastFt());
        } else if (e.target.dataset.hostNone) {
          DfirFacets.hosts.hideAll(hostFacets(DfirState.lastFt()));
          renderTimelineEvents(DfirState.lastFt());
        }
      });
      document.addEventListener("click", (e) => {
        if (!menu.hidden && !wrap.contains(e.target)) menu.hidden = true;
      });
    })();

    // IOC type filter dropdown (#169). Mirrors the source filter; handlers are scoped to the IOC
    // menu element so they never collide with the timeline's source filter. Re-renders the IOC list
    // off the same scoped list render() uses, so the facets/filter stay consistent under a scope.
    (function () {
      const wrap = document.getElementById("iocTypeLegendWrap");
      const btn = document.getElementById("iocTypeFilterBtn");
      const menu = document.getElementById("iocTypeFilterMenu");
      if (!wrap || !btn || !menu) return;
      const scopedIocs = () =>
        DfirState.lastState()
          ? DfirScope.project(DfirState.lastState()).iocs || []
          : [];
      const rerender = () => renderIocs(scopedIocs());
      btn.addEventListener("click", () => {
        menu.hidden = !menu.hidden;
      });
      menu.addEventListener("change", (e) => {
        if (!e.target.classList.contains("ioc-type-cb")) return;
        DfirFacets.iocTypes.toggle(e.target.value, !e.target.checked);
        rerender();
      });
      menu.addEventListener("click", (e) => {
        if (e.target.dataset.ioctypeAll) {
          DfirFacets.iocTypes.showAll();
          rerender();
        } else if (e.target.dataset.ioctypeNone) {
          DfirFacets.iocTypes.hideAll(iocTypeFacets(scopedIocs()));
          rerender();
        }
      });
      document.addEventListener("click", (e) => {
        if (!menu.hidden && !wrap.contains(e.target)) menu.hidden = true;
      });
    })();

    // IOC exclude-rule popover — list/add/remove. Add/delete just POST/DELETE; the server pushes
    // the updated state over the websocket (options.onState), which re-renders via render()/renderIocs()
    // → renderIocExcludeRules(), same reactive pattern as every other case mutation in this dashboard.
    (function () {
      const wrap = document.getElementById("iocExcludeWrap");
      const btn = document.getElementById("iocExcludeBtn");
      const menu = document.getElementById("iocExcludeMenu");
      if (!wrap || !btn || !menu) return;
      btn.addEventListener("click", () => {
        menu.hidden = !menu.hidden;
      });
      document
        .getElementById("iocExcludeAddBtn")
        .addEventListener("click", () => {
          const caseId = document.getElementById("caseId").value.trim();
          const msg = document.getElementById("iocExcludeMsg");
          const pattern = document
            .getElementById("iocExcludePattern")
            .value.trim();
          if (!caseId || !pattern) {
            msg.textContent = "pattern is required";
            return;
          }
          if (
            !confirm(
              `Add this exclude rule?\n\nAny IOC in this case currently matching "${pattern}" (${document.getElementById("iocExcludeMode").value}) will be permanently removed and never re-imported or enriched. This cannot be undone.`,
            )
          )
            return;
          const body = {
            match: document.getElementById("iocExcludeMode").value,
            pattern,
            note: document.getElementById("iocExcludeNote").value.trim(),
          };
          msg.textContent = "adding…";
          fetch(`/cases/${encodeURIComponent(caseId)}/ioc-exclude`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(body),
          })
            .then(async (r) => {
              const j = await r.json().catch(() => ({}));
              if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
              return j;
            })
            .then((j) => {
              msg.textContent = `added — purged ${j.purged} IOC${j.purged === 1 ? "" : "s"}`;
              document.getElementById("iocExcludePattern").value = "";
              document.getElementById("iocExcludeNote").value = "";
              setTimeout(() => {
                msg.textContent = "";
              }, 3000);
            })
            .catch((e) => {
              msg.textContent = "failed: " + e.message;
            });
        });
      menu.addEventListener("click", (e) => {
        const del = e.target.closest(".iex-del");
        if (!del) return;
        const caseId = document.getElementById("caseId").value.trim();
        if (!caseId) return;
        fetch(
          `/cases/${encodeURIComponent(caseId)}/ioc-exclude/${del.dataset.id}`,
          { method: "DELETE" },
        ).catch(() => {});
      });
      document.addEventListener("click", (e) => {
        if (!menu.hidden && !wrap.contains(e.target)) menu.hidden = true;
      });
    })();

    // Re-order the timeline when a column sort arrow (▲/▼) is clicked; persist the choice (#104).
    // The header is re-rendered on each render(), so delegate off the persistent #forensicTimeline.
    document
      .getElementById("forensicTimeline")
      .addEventListener("click", function (e) {
        const arrow = e.target.closest && e.target.closest(".tl-arrow");
        if (!arrow) return;
        timelineSort = {
          key: arrow.getAttribute("data-sortkey"),
          dir: arrow.getAttribute("data-sortdir"),
        };
        try {
          localStorage.setItem(
            "dfir_timeline_sort",
            timelineSort.key + ":" + timelineSort.dir,
          );
        } catch {}
        renderTimelineEvents(DfirState.lastFt());
      });

    // Re-render findings when the confidence filter changes, and persist the choice per-case
    // (debounced) so it survives a page reload — see loadConfidenceControl/saveConfidenceControl.
    document
      .getElementById("confFilter")
      .addEventListener("input", function () {
        if (DfirState.lastState()) render(DfirState.lastState());
        const caseId = document.getElementById("caseId").value.trim();
        if (caseId)
          saveConfidenceControl(caseId, parseInt(this.value, 10) || 0);
      });

    // The two finding-origin lenses: re-render, then persist per case. Same shape as the
    // confidence filter above, minus the debounce — see saveFindingOriginFilters for why.
    for (const lensId of ["hideAutoFindings", "hideGapFindings"]) {
      document.getElementById(lensId).addEventListener("change", function () {
        if (DfirState.lastState()) render(DfirState.lastState());
        const caseId = document.getElementById("caseId").value.trim();
        if (caseId)
          saveFindingOriginFilters(caseId, { [lensId]: this.checked });
      });
    }

    // One-click deploy of a structured collection directive (investigation-guidance #8, phase 3).
    // Delegated (the next-steps / key-questions HTML is re-rendered on every synthesis). Confirms, then
    // POSTs to the case collect-directive route which resolves the artifact VQL and launches the
    // collection on the (known, enrolled) host. The Deploy button is only rendered for a known case host.
    document.addEventListener("click", async (ev) => {
      const btn =
        ev.target && ev.target.closest && ev.target.closest(".collect-deploy");
      if (!btn || btn.disabled) return;
      const host = btn.getAttribute("data-host");
      const artifact = btn.getAttribute("data-artifact") || "";
      const logSource = btn.getAttribute("data-logsource") || "";
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId || !host) return;
      if (
        !confirm(
          `Deploy a Velociraptor collection on ${host}?\n\nArtifact/source: ${artifact || logSource || "(auto)"}`,
        )
      )
        return;
      const orig = btn.textContent;
      btn.disabled = true;
      btn.textContent = "deploying…";
      try {
        const r = await fetch(
          `/cases/${encodeURIComponent(caseId)}/velociraptor/collect-directive`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ hostname: host, artifact, logSource }),
          },
        );
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
        btn.textContent = `✓ ${j.artifact || "collection"} launched`;
        btn.classList.add("collect-done");
      } catch (e) {
        btn.disabled = false;
        btn.textContent = orig;
        alert(`Collection failed: ${e.message}`);
      }
    });

    document
      .getElementById("collectionPlan")
      .addEventListener("click", async (e) => {
        const setBtn = e.target.closest("[data-cp-set]");
        const clearBtn = e.target.closest("[data-cp-clear]");
        if (!setBtn && !clearBtn) return;
        const caseId = document.getElementById("caseId").value.trim();
        if (!caseId) return;
        const stepId = setBtn ? setBtn.dataset.cpSet : clearBtn.dataset.cpClear;
        const url = `/cases/${encodeURIComponent(caseId)}/collection-plan/${encodeURIComponent(stepId)}`;
        try {
          if (setBtn) {
            const state = setBtn.dataset.cpState;
            const reason =
              prompt(
                state === "na"
                  ? "Why does this not apply?"
                  : "Where is this evidence?",
              ) ?? "";
            await fetch(url, {
              method: "PUT",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ state, reason }),
            });
          } else {
            await fetch(url, { method: "DELETE" });
          }
        } catch {
          /* transient — the next render re-reads the truth from the server */
        }
        if (typeof renderCollectionPlan === "function") renderCollectionPlan();
      });
  }

  window.initTimelineControls = initTimelineControls;
})();
