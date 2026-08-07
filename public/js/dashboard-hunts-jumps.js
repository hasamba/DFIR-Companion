// AI-suggested Velociraptor hunts, and the cross-panel jump helpers — extracted from
// dashboard.html (issue #415, tier 3).
//
// Fourth block freed by measuring the spine rather than the section. The 1,145-line "Activity Log"
// banner has now yielded the kill chain (163), customer exposure and false positives (276) and
// this (236); what is left under it is 111 lines — the log itself, dfirFeatureUnavailable, and the
// facade-report table that names every stubbed feature.
//
// No initializer: nothing here runs at load. The jump helpers are called from links and from the
// hash router; doSuggestHunts from the toolbar button.
(function () {
  "use strict";

  function doSuggestHunts() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const btn = document.getElementById("suggestHuntsBtn");
    const msg = document.getElementById("suggestHuntsMsg");
    const el = document.getElementById("veloHuntSuggest");
    if (btn) btn.disabled = true;
    if (msg) msg.textContent = "thinking… (one AI call over the findings)";
    vhsSource = "fleet"; // #157 findings-driven hunts
    fetch(`/cases/${caseId}/velociraptor/suggest-hunts`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          if (msg) msg.textContent = "";
          el.innerHTML = `<div class="vhs-empty" data-safe-style="color:var(--sev-high)">error: ${esc(j.error || "could not generate hunts")} — restart the companion server if this 404s</div>`;
          return;
        }
        renderVeloHuntSuggest(j.suggestions || []);
        if (msg)
          msg.textContent = (j.suggestions || []).length
            ? `${j.suggestions.length} hunt(s) proposed`
            : "";
      })
      .catch((e) => {
        if (msg) msg.textContent = "";
        el.innerHTML = `<div class="vhs-empty" data-safe-style="color:var(--sev-high)">error: ${esc(e.message)}</div>`;
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }

  function renderVeloHuntSuggest(suggestions) {
    const el = document.getElementById("veloHuntSuggest");
    if (!el) return;
    if (!suggestions.length) {
      el.innerHTML = `<div class="vhs-empty">No fleet-hunts proposed. The AI found nothing fleet-wide to hunt for — try after running synthesis so findings exist, or add more evidence.</div>`;
      return;
    }
    vhsFlat = [...suggestions].sort(
      (a, b) =>
        (VHS_SEV_RANK[a.severity] ?? 9) - (VHS_SEV_RANK[b.severity] ?? 9),
    );
    const ordered = vhsFlat;
    const caveat = `<div class="vhs-caveat">⚠ AI-generated VQL — review each query before deploying. Deploying launches a hunt across ALL enrolled endpoints.${veloEnabled ? "" : " The Velociraptor API is not configured, so Deploy is disabled — copy the VQL to run it yourself."}</div>`;
    const cards = ordered
      .map((s, idx) => {
        const sev = s.severity || "Medium";
        const sevColor = VHS_SEV_COLOR[sev] || "#9aa4b2";
        const sevBadge = `<span class="vhs-sev" data-safe-style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}55">${esc(sev)}</span>`;
        const techs = (s.mitreTechniques || [])
          .map((t) => {
            const u = attackUrl(t);
            return u
              ? `<a href="${escAttr(u)}" target="_blank" rel="noopener" class="vhs-tech">${esc(t)}</a>`
              : `<span class="vhs-tech">${esc(t)}</span>`;
          })
          .join("");
        const rationale = s.rationale
          ? `<div class="vhs-rationale">${esc(s.rationale)}</div>`
          : "";
        const cites = citeFindings(s.relatedFindingIds);
        const deployBtn = veloEnabled
          ? `<button class="vhs-deploy" data-idx="${idx}" title="Launch this hunt across ALL enrolled Velociraptor clients">▶ Deploy hunt (all clients)</button>`
          : `<button class="vhs-deploy" disabled title="Velociraptor API not configured — set the API config path in Settings → Integrations, then restart the server">▶ Deploy hunt (all clients)</button>`;
        // Per-card regenerate (fleet hunts only — technique hunts come from the adversary panel's "hunt
        // this"): ask the AI for a DIFFERENT take when this VQL is bad/won't compile. Mirrors the playbook.
        const regenBtn =
          vhsSource === "fleet"
            ? `<button class="vhs-regen" data-idx="${idx}" title="Ask the AI for a different hunt for this finding (e.g. if this VQL won't compile)">↻ Regenerate</button>`
            : "";
        return (
          `<div class="vhs-card">` +
          `<div class="vhs-head"><span class="vhs-title">${esc(s.title)}</span>${sevBadge}</div>` +
          rationale +
          (cites
            ? `<div class="vhs-rationale" data-safe-style="color:var(--text-muted)">Cites: ${cites}</div>`
            : "") +
          (techs ? `<div class="vhs-techs">${techs}</div>` : "") +
          `<textarea class="vhs-vql" id="vhsQ${idx}" spellcheck="false">${esc(s.vql)}</textarea>` +
          `<div class="vhs-actions"><button class="vhs-copy" data-idx="${idx}">Copy VQL</button>${regenBtn}${deployBtn}</div>` +
          `<div class="vhs-res" id="vhsRes${idx}"></div>` +
          `</div>`
        );
      })
      .join("");
    el.innerHTML = caveat + `<div class="vhs-list">${cards}</div>`;
    // Stash the titles for the deploy description (the textarea only holds VQL).
    el.querySelectorAll(".vhs-copy").forEach(
      (b) =>
        (b.onclick = () => {
          const q = document.getElementById("vhsQ" + b.dataset.idx);
          navigator.clipboard
            .writeText(q ? q.value : "")
            .then(() => {
              b.textContent = "Copied ✓";
              b.classList.add("copied");
              setTimeout(() => {
                b.textContent = "Copy VQL";
                b.classList.remove("copied");
              }, 1500);
            })
            .catch(() => {
              b.textContent = "copy failed";
            });
        }),
    );
    el.querySelectorAll(".vhs-deploy:not([disabled])").forEach(
      (b) =>
        (b.onclick = () => {
          const idx = b.dataset.idx;
          const q = document.getElementById("vhsQ" + idx);
          const title =
            (ordered[idx] && ordered[idx].title) || "DFIR fleet hunt";
          const mitre = (ordered[idx] && ordered[idx].mitreTechniques) || [];
          const caseId = document.getElementById("caseId").value.trim();
          launchHuntInto(
            q ? q.value : "",
            title,
            document.getElementById("vhsRes" + idx),
            b,
            { caseId, title, source: vhsSource, mitre },
          ); // #157 record the deploy
        }),
    );
    el.querySelectorAll(".vhs-regen").forEach(
      (b) => (b.onclick = () => regenVeloHunt(b.dataset.idx, b)),
    );
  }

  // Regenerate ONE fleet-hunt suggestion — asks the AI for a different VQL (excluding the current,
  // bad one), swaps it into vhsFlat, and re-renders. Mirrors the playbook hunt regen (#157 / #57).
  function regenVeloHunt(idx, btn) {
    const caseId = document.getElementById("caseId").value.trim();
    const cur = vhsFlat[idx];
    if (!caseId || !cur) return;
    const q = document.getElementById("vhsQ" + idx);
    const excludeVql = q && q.value.trim() ? q.value : cur.vql;
    const msg = document.getElementById("suggestHuntsMsg");
    const orig = btn.textContent;
    btn.disabled = true;
    btn.textContent = "⏳ thinking…";
    if (msg) {
      msg.style.color = "var(--text-muted)";
      msg.textContent = "regenerating one hunt… (one AI call)";
    }
    fetch(`/cases/${caseId}/velociraptor/suggest-hunts`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ excludeVql }),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          if (msg) {
            msg.style.color = "var(--sev-high)";
            msg.textContent = "regen failed: " + (j.error || "unknown error");
          }
          btn.disabled = false;
          btn.textContent = orig;
          return;
        }
        const sugs = (j.suggestions || []).filter(Boolean);
        const replacement =
          sugs.find((s) => (s.vql || "").trim() !== excludeVql.trim()) ||
          sugs[0];
        if (!replacement) {
          if (msg) {
            msg.style.color = "var(--sev-high)";
            msg.textContent =
              "no alternative hunt generated — edit the VQL by hand";
          }
          btn.disabled = false;
          btn.textContent = orig;
          return;
        }
        vhsFlat[idx] = replacement;
        renderVeloHuntSuggest(vhsFlat); // re-render (vhsSource unchanged → regen buttons stay)
        if (msg) {
          msg.style.color = "var(--text-muted)";
          msg.textContent = "regenerated one hunt";
        }
      })
      .catch((e) => {
        if (msg) {
          msg.style.color = "var(--sev-high)";
          msg.textContent = "regen failed: " + e.message;
        }
        btn.disabled = false;
        btn.textContent = orig;
      });
  }

  // Scroll the timeline table to a row currently in the DOM and flash it (the reverse of the ring
  // sync). Returns true if the row was found on the visible page, false otherwise.
  function swLocateInTable(id) {
    const rows = document.querySelectorAll("#forensicTimeline .ev-row");
    for (const row of rows) {
      if (row.getAttribute("data-evid") === String(id)) {
        row.scrollIntoView({ behavior: "smooth", block: "center" });
        row.classList.remove("ev-flash");
        void row.offsetWidth; // restart the animation
        row.classList.add("ev-flash");
        setTimeout(() => row.classList.remove("ev-flash"), 1600);
        return true;
      }
    }
    return false;
  }

  // Reset the forensic-timeline VIEW filters (severity / source / starred / search / time range) so a
  // targeted event can't be hidden. Used by jumpToEvent when the event isn't on the current page —
  // only called when the row is genuinely hidden, so a no-filter view is left untouched.
  // The analyst's "clear filters", now one commit and one redraw. The facets are a separate owner
  // so they are cleared alongside; everything else belongs to DfirTimelineView.
  function resetTimelineViewFilters() {
    DfirFacets.sources.showAll();
    _srcMenuSig = "";
    DfirFacets.origins.showAll();
    _originMenuSig = "";
    DfirFacets.hosts.showAll();
    _hostMenuSig = "";
    DfirTimelineView.clearFilters();
    forgetPersistedExcludeTerms();
  }
  // Both filter-clearing paths drop the exclude terms, so both must drop the saved copy.
  function forgetPersistedExcludeTerms() {
    try {
      localStorage.setItem("dfir.excludeTerms", "[]");
    } catch {}
  }

  // Filter the forensic timeline to EXACTLY a set of event ids (e.g. every event behind a Timeline
  // Anomaly bucket) so the analyst sees all of them, not just the first. Clears other view filters
  // first so none of the targeted events stay hidden, expands the section, scrolls it into view.
  function filterTimelineToEventIds(ids, label) {
    const list = (ids || []).map(String).filter(Boolean);
    if (!list.length) return;
    DfirFacets.sources.showAll();
    _srcMenuSig = "";
    DfirFacets.origins.showAll();
    _originMenuSig = "";
    DfirFacets.hosts.showAll();
    _hostMenuSig = "";
    // ONE paint, with the id filter already committed. This used to reset (two full renders, both
    // showing the filter it had just cleared) and only apply the ids on a third.
    DfirTimelineView.filterToEventIds(list, label);
    forgetPersistedExcludeTerms(); // cleared in memory; must not return on reload
    const sec = document.getElementById("sec-timeline");
    if (sec) {
      sec.classList.remove("collapsed");
      sec.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }
  function clearEvIdFilter() {
    DfirTimelineView.clearEventIds();
  }
  // Render (or hide) the chip that shows the active "only these N events" filter + a Clear button.
  function renderEvIdFilterChip(shown, _total) {
    const el = document.getElementById("evIdFilterChip");
    if (!el) return;
    if (!DfirTimelineView.eventIdFilterActive()) {
      el.style.display = "none";
      el.innerHTML = "";
      return;
    }
    const n = DfirTimelineView.eventIdCount();
    el.style.display = "";
    el.innerHTML =
      `<span data-safe-style="color:var(--accent)">⧉ Showing ${shown} of ${n} event${n !== 1 ? "s" : ""} in this group` +
      `${DfirTimelineView.eventIdLabel() ? " — " + esc(DfirTimelineView.eventIdLabel()) : ""}</span>` +
      ` <button type="button" data-act="clearEvIdFilter" data-safe-style="margin-left:8px;font-size:11px;background:var(--border-color);border:none;color:var(--text-primary);border-radius:3px;padding:2px 8px;cursor:pointer" title="Clear this filter and show the whole timeline">✕ Clear, show all</button>`;
  }

  // Reveal a forensic event by id and scroll+flash it — used by the Evidence panel's supporting-event
  // links. The timeline is PAGINATED and FILTERABLE, so the target row may not be in the DOM: expand
  // the section, and if the row isn't on the current page, clear the view filters that could hide it,
  // page to where it lands, re-render, then locate.
  function jumpToEvent(id) {
    id = String(id);
    const sec = document.getElementById("sec-timeline");
    if (sec) sec.classList.remove("collapsed");
    if (swLocateInTable(id)) return; // already on the current page
    if (!(DfirState.lastFt() || []).some((e) => String(e.id) === id)) return; // not in the in-scope timeline
    resetTimelineViewFilters(); // unhide it if a filter excluded it
    // Read fresh at each use rather than held in a local. The cached value was correct — nothing
    // between these lines replaces it — but the no-stale-snapshot gate cannot see that through
    // this module's IIFE wrapper, and "do not hold a snapshot across a refresher" is the rule it
    // enforces. Obeying it costs two extra reads and removes the question.
    const sorted = sortTimelineEvents((DfirState.lastFt() || []).slice());
    const idx = sorted.findIndex((e) => String(e.id) === id);
    if (idx >= 0 && tlPageSize > 0) tlPage = Math.floor(idx / tlPageSize); // page the event lands on
    _tlKeepPage = true; // don't let the re-render reset the page
    renderTimelineEvents(DfirState.lastFt() || []);
    swLocateInTable(id);
  }

  function jumpToEventFromHash() {
    const m = /^#event=(.+)$/.exec(location.hash);
    if (m) jumpToEvent(decodeURIComponent(m[1]));
  }

  // Jump from a timeline event's finding link to that finding in the Findings section,
  // expanding the section if collapsed, then scroll + flash it (reuses the ev-flash animation).
  function jumpToFinding(fid) {
    const sec = document.getElementById("sec-findings");
    if (sec) sec.classList.remove("collapsed");
    const target = [...document.querySelectorAll("#findings .finding")].find(
      (div) => div.getAttribute("data-fid") === fid,
    );
    if (!target) return;
    target.scrollIntoView({ behavior: "smooth", block: "center" });
    target.classList.remove("ev-flash");
    void target.offsetWidth; // restart the animation
    target.classList.add("ev-flash");
    setTimeout(() => target.classList.remove("ev-flash"), 1600);
  }

  function jumpToTrackedItem(sectionId, selector, attribute, id) {
    const sec = document.getElementById(sectionId);
    if (sec) sec.classList.remove("collapsed");
    const target = [...document.querySelectorAll(selector)].find(
      (element) => element.getAttribute(attribute) === String(id),
    );
    if (!target) return;
    target.scrollIntoView({ behavior: "smooth", block: "center" });
    target.classList.remove("ev-flash");
    void target.offsetWidth;
    target.classList.add("ev-flash");
    setTimeout(() => target.classList.remove("ev-flash"), 1600);
  }

  function jumpToHypothesis(id) {
    jumpToTrackedItem("sec-hypotheses", "#hypList .hyp", "data-id", id);
  }

  function jumpToQuestion(id) {
    jumpToTrackedItem(
      "sec-questions",
      "#keyQuestions .qrow",
      "data-question-id",
      id,
    );
  }

  window.clearEvIdFilter = clearEvIdFilter;
  window.doSuggestHunts = doSuggestHunts;
  window.filterTimelineToEventIds = filterTimelineToEventIds;
  window.jumpToEvent = jumpToEvent;
  window.jumpToEventFromHash = jumpToEventFromHash;
  window.jumpToFinding = jumpToFinding;
  window.jumpToHypothesis = jumpToHypothesis;
  window.jumpToQuestion = jumpToQuestion;
  window.renderEvIdFilterChip = renderEvIdFilterChip;
  window.renderVeloHuntSuggest = renderVeloHuntSuggest;
})();
