// Customer exposure, false-positive markers, learned patterns and source trust — extracted
// from dashboard.html (issue #415, tier 3).
//
// Four features that shared a banner with renderIocs, which is why the whole 637-line block read
// as core machinery and sat untouched. Splitting the banner immediately above renderIocs left
// these 276 lines with ZERO escapes.
//
// That is the second block freed this way after the kill chain, and the pattern is now explicit:
// a section flagged core because it CONTAINS a spine function is not 637 lines of spine. The spine
// is 843 lines across six functions; everything else in those sections is ordinary feature code.
(function () {
  "use strict";

  function renderCustomerExposure(j) {
    const el = document.getElementById("customerExposure");
    if (!el) return;
    const targets = j.targets || { domains: [], emails: [] };
    const effective = j.effectiveTargets || targets;
    // Chip state: manual domains/emails (removable) + emails auto-discovered by the investigation
    // (shown as dashed "auto" chips, always included). New/typed items appear as chips and are
    // included by default — remove an unwanted one with its ×.
    ceDomains = (targets.domains || []).slice();
    ceEmails = (targets.emails || []).slice();
    ceAutoDomains = (effective.domains || []).filter(
      (d) => !ceDomains.includes(d),
    );
    ceAutoEmails = (effective.emails || []).filter(
      (e) => !ceEmails.includes(e),
    );
    renderCeChips();
    const exposure = j.exposure || {};
    const results = exposure.results || [];
    const errors = exposure.errors || [];
    const configured = !!j.anyConfigured;
    document.getElementById("runCustomerExposure").disabled = !configured;
    // Provider picker (like the enrichment per-source selection): a checkbox per configured
    // provider, checked when in the saved selection (or all when no selection is stored).
    const allProviders = j.providers || [];
    const sel =
      targets.providers && targets.providers.length ? targets.providers : null; // null = all
    const provBox = document.getElementById("ceProviders");
    if (provBox) {
      provBox.innerHTML = allProviders.length
        ? "Run on: " +
          allProviders
            .map(
              (name) =>
                `<label data-safe-style="margin-right:12px;cursor:pointer"><input type="checkbox" class="ce-prov" value="${escAttr(name)}" ${!sel || sel.includes(name) ? "checked" : ""}> ${esc(name)}</label>`,
            )
            .join("")
        : "<span data-safe-style='color:var(--sev-high)'>No exposure providers configured — set DFIR_LEAKCHECK_KEY / DFIR_HIBP_KEY / DFIR_DEHASHED_KEY / DFIR_SHODAN_KEY / DFIR_CROWDSTRIKE_CLIENT_ID and restart.</span>";
    }
    // Show the providers that ACTUALLY ran in the last check (exposure.providers), not every
    // configured provider (j.providers) — otherwise a Shodan-only run still listed LeakCheck.
    const providers = (exposure.providers || []).join(", ") || "none";
    const checked = exposure.checkedAt
      ? `Last checked ${esc(new Date(exposure.checkedAt).toLocaleString())}`
      : "Not checked yet";
    const targetLine = `Domains: ${(effective.domains || []).map(esc).join(", ") || "none"} · Emails: ${(effective.emails || []).map(esc).join(", ") || "none"}`;
    // Show only rows where a provider actually found something — clean "checked, no breach"
    // rows are hidden (mirrors hasExposureFinding in customerExposure.ts; the providers/targets
    // lines above still record what was checked).
    const found = results.filter(
      (r) =>
        (r.breach && String(r.breach).trim()) ||
        (r.exposedData && r.exposedData.length) ||
        r.secretPresent,
    );
    const rows = found.length
      ? found
          .map((r) => {
            // The headline (breach / exposed host) links to the provider's report when one exists
            // — e.g. Shodan's https://www.shodan.io/host/<ip>.
            const head = r.breach
              ? r.sourceUrl
                ? ` · <a href="${escAttr(r.sourceUrl)}" target="_blank" rel="noopener" data-safe-style="color:var(--accent);text-decoration:none"><strong>${esc(r.breach)}</strong> ↗</a>`
                : ` · <strong>${esc(r.breach)}</strong>`
              : "";
            return (
              `<div>${esc(r.provider)} · <span data-safe-style="color:var(--text-muted)">${esc(r.targetType)}:</span> ${esc(r.target)}` +
              `${r.email ? ` · ${esc(r.email)}` : ""}` +
              head +
              `${r.breachDate ? ` · ${esc(r.breachDate)}` : ""}` +
              `${r.secretPresent ? ` · <span class="sev-High">credential material present</span>` : ""}` +
              `${r.exposedData && r.exposedData.length ? ` · <small>${esc(r.exposedData.slice(0, 6).join(", "))}</small>` : ""}</div>`
            );
          })
          .join("")
      : "<div data-safe-style='color:var(--text-muted)'>No exposures found.</div>";
    const errs = errors.length
      ? `<details><summary>${errors.length} provider error${errors.length !== 1 ? "s" : ""}</summary>${errors.map((e) => `<div data-safe-style="color:var(--sev-high)">${esc(e.provider)} ${esc(e.targetType)} ${esc(e.target)}: ${esc(e.error)}</div>`).join("")}</details>`
      : "";
    el.innerHTML = `<div data-safe-style="color:var(--text-muted);font-size:12px">${checked} · Providers: ${esc(providers)}<br>${targetLine}</div>${rows}${errs}`;
  }
  function loadCustomerExposure(caseId) {
    fetch(`/cases/${caseId}/customer-exposure`)
      .then((r) => r.json())
      .then(renderCustomerExposure)
      .catch(() => {
        document.getElementById("customerExposure").innerHTML =
          "<span data-safe-style='color:var(--sev-high)'>Customer exposure endpoints unavailable — restart the companion server.</span>";
      });
  }
  let ceDomains = [],
    ceEmails = [],
    ceAutoDomains = [],
    ceAutoEmails = [];
  function selectedExposureProviders() {
    return Array.from(document.querySelectorAll(".ce-prov:checked")).map(
      (c) => c.value,
    );
  }
  function renderCeChips() {
    const dom = document.getElementById("ceDomainChips");
    const em = document.getElementById("ceEmailChips");
    if (dom)
      dom.innerHTML =
        ceDomains.map((d) => ceChip(d, "domain", false)).join("") +
          ceAutoDomains.map((d) => ceChip(d, "domain", true)).join("") ||
        "<span data-safe-style='color:var(--text-faint);font-size:11px'>no customer domains yet</span>";
    if (em)
      em.innerHTML =
        ceEmails.map((e) => ceChip(e, "email", false)).join("") +
          ceAutoEmails.map((e) => ceChip(e, "email", true)).join("") ||
        "<span data-safe-style='color:var(--text-faint);font-size:11px'>no customer emails yet</span>";
  }
  // Persist the current chip + provider state. Called on every add/remove/toggle so a new item is
  // active immediately (no separate Save step), then reload to refresh auto-discovered emails.
  function ceAutosaveTargets() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    renderCeChips();
    const msg = document.getElementById("customerExposureMsg");
    msg.textContent = "saving…";
    fetch(`/cases/${encodeURIComponent(caseId)}/customer-exposure/targets`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        domains: ceDomains,
        emails: ceEmails,
        providers: selectedExposureProviders(),
      }),
    })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
        return j;
      })
      .then(() => {
        msg.textContent = "saved";
        loadCustomerExposure(caseId);
        setTimeout(() => {
          if (msg.textContent === "saved") msg.textContent = "";
        }, 1500);
      })
      .catch((e) => {
        msg.textContent = "save failed: " + e.message;
      });
  }
  function ceAddTarget(kind, value) {
    const n = String(value || "")
      .trim()
      .toLowerCase();
    if (!n) return;
    const list = kind === "domain" ? ceDomains : ceEmails;
    if (!list.includes(n)) {
      list.push(n);
      ceAutosaveTargets();
    }
  }
  function ceRemoveTarget(kind, value) {
    if (kind === "domain") ceDomains = ceDomains.filter((d) => d !== value);
    else ceEmails = ceEmails.filter((e) => e !== value);
    ceAutosaveTargets();
  }
  function runCustomerExposureCheck() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const msg = document.getElementById("customerExposureMsg");
    msg.textContent = "checking…";
    fetch(`/cases/${encodeURIComponent(caseId)}/customer-exposure/check`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ providers: selectedExposureProviders() }),
    })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
        return j;
      })
      .then((j) => {
        msg.textContent = `checked: ${j.results.length} hit(s), ${j.errors.length} error(s)`;
        loadCustomerExposure(caseId);
      })
      .catch((e) => {
        msg.textContent = "failed: " + e.message;
      });
  }

  function renderFalsePositives(markers, redraw) {
    fpMarkers = markers || [];
    const el = document.getElementById("false-positive");
    // The global filter toolbar (search + exclude terms) scopes this panel too, same as the
    // Timeline/Findings/IOCs — matched against kind/ref/label/reason/note (see _fpMatchesSearch).
    const q = DfirTimelineView.search();
    // Most-recently-marked first, so a fresh mark-as-FP surfaces at the top instead of getting
    // buried at the bottom of a long list (markedAt is an ISO timestamp; unparsable sorts last).
    const sorted = [...fpMarkers].sort(
      (a, b) => (Date.parse(b.markedAt) || 0) - (Date.parse(a.markedAt) || 0),
    );
    const visible = sorted.filter(
      (m) =>
        (!q || _fpMatchesSearch(m, q)) &&
        !(
          DfirTimelineView.excludeTerms().length &&
          _fpMatchesExclude(m, DfirTimelineView.excludeTerms())
        ) &&
        (!fpReasonFilter || m.reason === fpReasonFilter),
    );
    // For event markers, prefer the human-readable label (the event description)
    // over the opaque event id stored as ref.
    el.innerHTML = visible.length
      ? visible
          .map((m) => {
            const shown = m.kind === "event" && m.label ? m.label : m.ref;
            return (
              `<div class="fp-marker-row">` +
              `<span class="fp-marker-kind">${esc(m.kind)}</span>` +
              `<span class="fp-marker-ref">${esc(shown)}</span>` +
              (m.reason
                ? `<span class="fp-marker-reason">${esc(m.reason)}</span>`
                : "") +
              (m.note
                ? `<span class="fp-marker-note">${esc(m.note)}</span>`
                : "") +
              `<button class="unfp-btn" data-id="${escAttr(m.id)}">un-mark</button></div>`
            );
          })
          .join("")
      : fpMarkers.length
        ? "<div data-safe-style='color:var(--text-muted)'>No false positives match the current filter.</div>"
        : "<div data-safe-style='color:var(--text-muted)'>Nothing marked false positive.</div>";
    const fpCountEl = document.getElementById("fpCount");
    if (fpCountEl) {
      fpCountEl.textContent =
        q || DfirTimelineView.excludeTerms().length || fpReasonFilter
          ? `(${visible.length} of ${fpMarkers.length})`
          : fpMarkers.length
            ? `(${fpMarkers.length})`
            : "";
    }
    // FP events are hidden from the timeline — re-render it with the new set. `redraw === false`
    // is DfirTimelineView's painter, whose action asks for `all` itself; see that module.
    if (redraw !== false && DfirState.lastState())
      render(DfirState.lastState());
  }
  // Event ids the client confirmed as a false positive (hidden from the forensic timeline view).
  function fpEventIdSet() {
    return new Set(
      fpMarkers
        .filter((m) => m.kind === "event")
        .map((m) => String(m.ref).trim().toLowerCase()),
    );
  }
  // IOC VALUES the client confirmed as a false positive (an IOC marker's ref is the indicator value,
  // not its id — see fpBtn("ioc", i.value)) — used by the "Hide FP/no-intel" checkbox.
  function fpIocValueSet() {
    return new Set(
      fpMarkers
        .filter((m) => m.kind === "ioc")
        .map((m) => String(m.ref).trim().toLowerCase()),
    );
  }
  // Finding TITLES the client confirmed as a false positive — findings are marked by title, not id
  // (see fpBtn("finding", f.title) and buildFalsePositiveMarker on the server). Hidden from the
  // Findings panel the instant the mark succeeds, rather than waiting for the background AI
  // re-synthesis to actually drop it from state (which can take many seconds) — see
  // isFindingFalsePositive below, used where `sorted` is built.
  function fpFindingTitleSet() {
    return new Set(
      fpMarkers
        .filter((m) => m.kind === "finding")
        .map((m) => String(m.ref).trim().toLowerCase()),
    );
  }

  function loadFalsePositives(caseId) {
    fetch(`/cases/${caseId}/false-positive`)
      .then((r) => r.json())
      .then(renderFalsePositives)
      .catch(() => {});
  }

  // Learned dismissal patterns (#65): read-only view of the recurring reasoned dismissals that synthesis
  // uses to DOWN-WEIGHT (not exclude) new look-alike activity. Sorted by recurrence.
  const LP_REASON_LABEL = {
    "known-good-tool": "known-good tool",
    "authorized-test": "authorized test",
    "detection-misfire": "detection misfire",
    duplicate: "duplicate",
    other: "other",
  };
  function renderLearnedPatterns(patterns) {
    const wrap = document.getElementById("learnedPatternsWrap");
    const el = document.getElementById("learnedPatterns");
    if (!wrap || !el) return;
    const list = Array.isArray(patterns)
      ? patterns.slice().sort((a, b) => (b.count || 0) - (a.count || 0))
      : [];
    if (!list.length) {
      wrap.style.display = "none";
      el.innerHTML = "";
      return;
    }
    wrap.style.display = "";
    el.innerHTML = list
      .map(
        (p) =>
          `<div class="lp-row"><span class="lp-sig">${esc(p.signature || "")}</span>` +
          `<span class="fp-marker-reason">${esc(LP_REASON_LABEL[p.reason] || p.reason || "")}</span>` +
          `<span class="lp-count" title="Dismissed ${p.count}× on this case">×${Number(p.count) || 1}</span></div>`,
      )
      .join("");
  }
  function loadLearnedPatterns(caseId) {
    fetch(`/cases/${caseId}/learned-patterns`)
      .then((r) => (r.ok ? r.json() : []))
      .then(renderLearnedPatterns)
      .catch(() => {});
  }

  // Source trust (#66): show each known source's default weight with an editable per-case override.
  let sourceTrustDefaults = {};
  function renderSourceTrust(payload) {
    sourceTrustDefaults = (payload && payload.defaults) || {};
    const overrides = (payload && payload.overrides) || {};
    const el = document.getElementById("sourceTrustList");
    if (!el) return;
    const keys = Object.keys(sourceTrustDefaults).sort(
      (a, b) =>
        sourceTrustDefaults[b] - sourceTrustDefaults[a] || a.localeCompare(b),
    );
    el.innerHTML = keys
      .map(
        (k) =>
          `<div class="st-row"><span class="st-name">${esc(k)}</span>` +
          `<span class="st-def" title="Built-in default">${sourceTrustDefaults[k].toFixed(2)}</span>` +
          `<input type="number" min="0" max="1" step="0.05" data-src="${escAttr(k)}" placeholder="${sourceTrustDefaults[k].toFixed(2)}" value="${overrides[k] != null ? overrides[k] : ""}" /></div>`,
      )
      .join("");
  }
  function loadSourceTrust(caseId) {
    fetch(`/cases/${caseId}/source-trust`)
      .then((r) => (r.ok ? r.json() : null))
      .then((p) => {
        if (p) renderSourceTrust(p);
      })
      .catch(() => {});
  }

  // Event delegation for the dynamically-rendered mark-FP / un-mark buttons.

  // The FP reason filter, the source-trust save button and the delegated click block.
  function initExposureFp() {
    document
      .getElementById("fpReasonFilterSel")
      .addEventListener("change", function () {
        fpReasonFilter = this.value;
        renderFalsePositives(fpMarkers);
      });
    document
      .getElementById("sourceTrustSaveBtn")
      .addEventListener("click", function (e) {
        e.stopPropagation();
        const caseId = document.getElementById("caseId").value.trim();
        const msg = document.getElementById("sourceTrustMsg");
        if (!caseId) {
          msg.textContent = "open a case first";
          return;
        }
        const overrides = {};
        document
          .querySelectorAll("#sourceTrustList input[data-src]")
          .forEach((inp) => {
            const v = inp.value.trim();
            if (v !== "") {
              const n = Number(v);
              if (n >= 0 && n <= 1) overrides[inp.getAttribute("data-src")] = n;
            }
          });
        msg.textContent = "saving…";
        fetch(`/cases/${caseId}/source-trust`, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ overrides }),
        })
          .then((r) => {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
          })
          .then((p) => {
            renderSourceTrust(p);
            msg.textContent = "saved — applies on next synthesis";
          })
          .catch((err) => {
            msg.textContent =
              "failed: " +
              err.message +
              " — restart the companion server if this 404s";
          });
      });
    document.addEventListener("click", (e) => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      const mark = e.target.closest(".fp-btn");
      if (mark) {
        const kind = mark.dataset.kind,
          ref = mark.dataset.ref,
          label = mark.dataset.label;
        openFalsePositiveModal(kind, ref, label != null ? label : ref, []);
        return;
      }
      const iocMerge = e.target.closest(".ioc-merge-btn");
      if (iocMerge) {
        const id = iocMerge.dataset.iocid;
        const cur = iocMerge.dataset.value;
        const type = iocMerge.dataset.ioctype;
        const candidates = dedupeIocsById(_lastRenderedIocs || [])
          .filter((i) => i.id !== id && i.type === type)
          .map((i) => ({ id: i.id, label: i.value }));
        openMergeModal(
          `Merge IOC "${cur}" into which ${type}?`,
          candidates,
          (into) =>
            fetch(`/cases/${caseId}/ioc-overrides/merge`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ from: id, into }),
            })
              .then((r) =>
                r.ok ? null : r.json().then((err) => Promise.reject(err.error)),
              )
              .then(() => {
                if (DfirState.lastState())
                  renderIocs(DfirState.lastState().iocs || []);
              }),
        );
        return;
      }
      const un = e.target.closest(".unfp-btn");
      if (un) {
        // Parse the marker id (`<kind>:<ref>`) so the reversal can be recorded in the Investigation
        // Log too — symmetric with the mark action (#221).
        const mid = un.dataset.id || "";
        const ci = mid.indexOf(":");
        const unKind = ci >= 0 ? mid.slice(0, ci) : "ioc";
        const unRef = ci >= 0 ? mid.slice(ci + 1) : mid;
        fetch(`/cases/${caseId}/false-positive/remove`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ id: un.dataset.id }),
        })
          .then((r) => {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
          })
          .then((markers) => {
            renderFalsePositives(markers);
            const tid = unKind === "ioc" ? qaResolveIocId(unRef, null) : unRef;
            qaAudit(caseId, unKind, tid, `un-marked false positive: ${unRef}`);
          })
          .catch(
            () =>
              (document.getElementById("status").textContent =
                "un-mark failed — restart the companion server."),
          );
      }
    });
  }

  window.initExposureFp = initExposureFp;
  window.ceAddTarget = ceAddTarget;
  window.ceAutosaveTargets = ceAutosaveTargets;
  window.ceRemoveTarget = ceRemoveTarget;
  window.fpEventIdSet = fpEventIdSet;
  window.fpFindingTitleSet = fpFindingTitleSet;
  window.fpIocValueSet = fpIocValueSet;
  window.loadCustomerExposure = loadCustomerExposure;
  window.loadFalsePositives = loadFalsePositives;
  window.loadLearnedPatterns = loadLearnedPatterns;
  window.loadSourceTrust = loadSourceTrust;
  window.renderFalsePositives = renderFalsePositives;
  window.runCustomerExposureCheck = runCustomerExposureCheck;
})();
