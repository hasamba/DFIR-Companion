// Search bar, time-range filter, scope controls and the modal wiring that sits with them
// (#415 tier 3).
//
// THE LARGEST WIRING-ONLY BLOCK IN THE FILE: 220 lines, nineteen statements, not one declaration
// and not one name anything outside calls. Three of the nineteen are self-calling IIFEs, which is
// the fifth, sixth and seventh in this PR — a `(function(){…})()` at module scope reads as
// deliberate and is the same load-time trap as any other DOM work in a <head> script.
//
// The enrichment guard that an earlier extraction left in the middle of this range did NOT come
// with it: it belongs to js/dashboard-enrichment.js and stays in the page.
(function () {
  function initSearchAndScope() {
    // --- Search bar + time-range filter listeners --------------------------------
    (function () {
      const gs = document.getElementById("globalSearch");
      const cs = document.getElementById("clearSearch");
      const ff = document.getElementById("filterFrom");
      const ft = document.getElementById("filterTo");
      const cfBtn = document.getElementById("clearFiltersBtn");
      const toggleBtn = document.getElementById("toggleSearchBar");
      const exIn = document.getElementById("excludeInput");
      const exChips = document.getElementById("excludeChips");
      const exClearBtn = document.getElementById("clearExcludeBtn");

      toggleBtn.addEventListener("click", () => {
        setSearchBarOpen(document.getElementById("searchFilterBar").hidden);
      });
      document
        .getElementById("closeSearchBar")
        .addEventListener("click", () => setSearchBarOpen(false));

      // Exclude filter (#216): each Enter (or comma) adds the current input as a new term; terms are
      // OR'd — a row is hidden if it matches ANY of them. A term may contain spaces (a phrase).
      renderExcludeChips();
      function addExcludeTerm(raw) {
        const term = raw.trim();
        if (!term) return;
        if (
          DfirTimelineView.excludeTerms().some(
            (t) => t.toLowerCase() === term.toLowerCase(),
          )
        )
          return; // no dupes
        setExcludeTerms([...DfirTimelineView.excludeTerms(), term]);
      }
      if (exIn) {
        exIn.addEventListener("keydown", (e) => {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            addExcludeTerm(exIn.value);
            exIn.value = "";
          } else if (
            e.key === "Backspace" &&
            !exIn.value &&
            DfirTimelineView.excludeTerms().length
          ) {
            setExcludeTerms(DfirTimelineView.excludeTerms().slice(0, -1)); // Backspace on empty input pops the last chip
          } else if (e.key === "Escape") {
            exIn.value = "";
            exIn.blur();
          }
        });
        exIn.addEventListener("blur", () => {
          if (exIn.value.trim()) {
            addExcludeTerm(exIn.value);
            exIn.value = "";
          }
        });
      }
      if (exChips) {
        exChips.addEventListener("click", (e) => {
          const btn = e.target.closest("button[data-i]");
          if (!btn) return;
          const i = parseInt(btn.dataset.i, 10);
          setExcludeTerms(
            DfirTimelineView.excludeTerms().filter((_, idx) => idx !== i),
          );
        });
      }
      if (exClearBtn)
        exClearBtn.addEventListener("click", () => setExcludeTerms([]));

      function applySearch() {
        DfirTimelineView.setSearch(gs.value);
      }
      window.applySearch = applySearch; // exposed for cross-section pivots (Login Graph "Open in Timeline")
      function applyTimeRange() {
        DfirTimelineView.setTimeWindow(
          utcInputToIso(ff.value),
          utcInputToIso(ft.value),
        );
      }

      gs.addEventListener("input", () => {
        clearTimeout(_searchDebounce);
        _searchDebounce = setTimeout(applySearch, 300);
      });
      gs.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
          if (gs.value) {
            gs.value = "";
            applySearch();
          } // first Esc clears the query…
          else {
            setSearchBarOpen(false);
            gs.blur();
          } // …a second one collapses the bar
        }
      });
      cs.addEventListener("click", () => {
        gs.value = "";
        applySearch();
        gs.focus();
      });

      ff.addEventListener("change", applyTimeRange);
      ft.addEventListener("change", applyTimeRange);
      cfBtn.addEventListener("click", () => {
        ff.value = "";
        ft.value = "";
        applyTimeRange();
      });

      // Press "/" to reveal + focus the search bar (when not already in a text field).
      document.addEventListener("keydown", (e) => {
        if (
          e.key === "/" &&
          document.activeElement.tagName !== "INPUT" &&
          document.activeElement.tagName !== "TEXTAREA"
        ) {
          e.preventDefault();
          setSearchBarOpen(true);
        }
      });
    })();

    // Per-section corroboration lens (#35): each title-bar select drives ONLY its own section, persisted
    // independently. (Replaces the former single global filter-bar control.)
    (function () {
      const wire = (id, get, set, rerender) => {
        const sel = document.getElementById(id);
        if (!sel) return;
        sel.value = String(get());
        sel.classList.toggle("active", get() > 1);
        sel.addEventListener("change", () => {
          const v = parseInt(sel.value, 10);
          set(v === 2 || v === 3 ? v : 0);
          sel.classList.toggle("active", get() > 1);
          rerender();
        });
      };
      wire(
        "corrobTimeline",
        () => DfirTimelineView.corrobTimeline(),
        (v) => {
          DfirTimelineView.setCorroboration("timeline", v);
          localStorage.setItem("dfir.corrob.timeline", String(v));
        },
        () => {},
      ); // the owner refreshes
      wire(
        "corrobIocs",
        () => DfirTimelineView.corrobIocs(),
        (v) => {
          DfirTimelineView.setCorroboration("iocs", v);
          localStorage.setItem("dfir.corrob.iocs", String(v));
        },
        () => {},
      );
      wire(
        "corrobFindings",
        () => DfirTimelineView.corrobFindings(),
        (v) => {
          _tlKeepPage = true;
          DfirTimelineView.setCorroboration("findings", v);
          localStorage.setItem("dfir.corrob.findings", String(v));
        },
        () => {},
      );
      // Risk lens (#63) — dedicated handler (accepts tier 2/3/4, which `wire` doesn't).
      const riskSel = document.getElementById("riskIocs");
      if (riskSel) {
        riskSel.value = String(riskIocsFilter);
        riskSel.classList.toggle("active", riskIocsFilter > 0);
        riskSel.addEventListener("change", () => {
          const v = parseInt(riskSel.value, 10);
          riskIocsFilter = v >= 2 && v <= 4 ? v : 0;
          localStorage.setItem("dfir.risk.iocs", String(riskIocsFilter));
          riskSel.classList.toggle("active", riskIocsFilter > 0);
          if (DfirState.lastState())
            renderIocs(DfirState.lastState().iocs || []);
        });
      }
    })();

    // IOC noise-reduction controls (#218-ish): sync initial UI state from the persisted preference
    // (the markup defaults all to ON, but a returning analyst may have turned one off) and wire each
    // checkbox's change event — the button ("Signal only") is handled in the delegated click listener
    // above since it's a toggle, not a native checkbox.
    (function () {
      const signalBtn = document.getElementById("iocSignalBtn");
      if (signalBtn) signalBtn.classList.toggle("active", showSignalIocsOnly);
      const noiseChk = document.getElementById("iocHideNoiseChk");
      if (noiseChk) {
        noiseChk.checked = hideFpNoIntel;
        noiseChk.addEventListener("change", () => {
          hideFpNoIntel = noiseChk.checked;
          localStorage.setItem("dfir.ioc.hideNoise", hideFpNoIntel ? "1" : "0");
          if (DfirState.lastState())
            renderIocs(DfirState.lastState().iocs || []);
        });
      }
      const sysPathChk = document.getElementById("iocHideSysPathsChk");
      if (sysPathChk) {
        sysPathChk.checked = hideSystemPaths;
        sysPathChk.addEventListener("change", () => {
          hideSystemPaths = sysPathChk.checked;
          localStorage.setItem(
            "dfir.ioc.hideSysPaths",
            hideSystemPaths ? "1" : "0",
          );
          if (DfirState.lastState())
            renderIocs(DfirState.lastState().iocs || []);
        });
      }
    })();

    document.getElementById("aiToggle").onclick = toggleAi;
    document.getElementById("applyScope").onclick = applyScope;
    document.getElementById("clearScope").onclick = () => {
      document.getElementById("scopeStart").value = "";
      document.getElementById("scopeEnd").value = "";
      applyScope();
    };
    // Relative presets: window = [latest activity − N hours, latest activity].
    document.querySelectorAll(".scope-preset").forEach((btn) => {
      btn.onclick = () => {
        const hours = Number(btn.dataset.hours);
        const anchor = latestEventMs();
        document.getElementById("scopeStart").value = isoToUtcInput(
          new Date(anchor - hours * 3600_000).toISOString(),
        );
        document.getElementById("scopeEnd").value = isoToUtcInput(
          new Date(anchor).toISOString(),
        );
        applyScope();
      };
    });
    document.getElementById("synthesize").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      const deep = !!document.getElementById("deepReasoning")?.checked;
      document.getElementById("status").textContent = deep
        ? "synthesizing (deep reasoning)…"
        : "synthesizing…";
      fetch(`/cases/${caseId}/synthesize`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ deepReasoning: deep }),
      })
        .then(async (r) => {
          if (r.status === 409) {
            const body = await r.json().catch(() => ({}));
            if (body.error === "presidio_approval_required") {
              if (typeof setPresidioPending === "function")
                setPresidioPending(body.findings);
              document.getElementById("status").textContent =
                "synthesis held — Presidio found new value(s) to review (see Anonymization)";
              return null;
            }
          }
          if (r.status === 423)
            return r.json().then((p) => {
              throw Object.assign(new Error(p.error || "Case is closed"), {
                locked: true,
              });
            });
          return r.json();
        })
        .then((p) => {
          if (!p) return; // handled above (409 presidio hold)
          if (p.error) {
            document.getElementById("status").textContent =
              "synthesis failed: " + p.error;
            return;
          }
          document.getElementById("status").textContent =
            `synthesized: ${p.findings} findings, ${p.mitreTechniques} techniques` +
            (p.attackerPath ? ", attack path" : "") +
            (p.narrativeTimeline ? ", narrative" : "");
          // refresh state in case the WS push was missed
          fetch(`/cases/${caseId}/state`)
            .then((r) => r.json())
            .then(render)
            .catch(() => {});
          loadSynthMeta(caseId);
        })
        .catch(
          (e) =>
            (document.getElementById("status").textContent =
              "synthesis error: " + e.message),
        );
    };
    // The #secondOpinion button and the #secondOpinionPanel handler moved to their own feature
    // (js/dashboard-second-opinion.js, #415). They were never search-scope's — an earlier
    // extraction swept them in, and three of that feature's bindings stayed in the page to be
    // read from here by bare name.
    document.getElementById("anonToggle").onclick = openAnonModal;
    document.getElementById("anonSave").onclick = saveAnon;
    document.getElementById("anonCancel").onclick = () =>
      document.getElementById("anonOverlay").classList.remove("open");
    document.getElementById("anonCustAdd").onclick = addCustomEntity;
    document.getElementById("anonCustVal").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        addCustomEntity();
      }
    });
    document.getElementById("anonOverlay").addEventListener("click", (e) => {
      if (e.target.id === "anonOverlay")
        document.getElementById("anonOverlay").classList.remove("open");
    });
  }

  window.initSearchAndScope = initSearchAndScope;
})();
