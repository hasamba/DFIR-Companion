// render() — the page's central redraw — extracted from dashboard.html (issue #415, tier 3).
//
// THIS IS NOT A FEATURE EXTRACTION, and it does not follow the facade's usual contract. Every
// other module here can go missing and cost one panel. render() has 17 call sites in the page
// and is called by 24 of the other modules; if it is absent the dashboard shows nothing.
//
// So render is deliberately NOT stubbed by js/dashboard-facade.js. A stub would return quietly
// and leave the analyst looking at an empty or stale dashboard with no indication — which is
// the one thing the facade's rule forbids: a stub may replace work, never evidence. Instead the
// facade detects it missing AT LOAD, before any call, and says so. Every call site in the page
// is guarded so the failure is one visible message rather than 24 console errors.
//
// The trade this makes is explicit: an inline script cannot fail to load and a module can, so
// this adds a failure mode the page did not have. It is here because #415's target requires it,
// and the mitigation is that the new failure is loud and immediate rather than silent.
(function () {
  "use strict";

  function render(rawState) {
    // Ignore a state response/WS push for a case the analyst has already left (#174) — otherwise
    // a slow response for an abandoned case load can silently overwrite the case now on screen.
    //
    // NO ACTIVE CASE COUNTS AS "LEFT", which is why the null check on activeCaseId is not here.
    // Cancelling a case load clears it, and the guard has to reject on that: with `activeCaseId &&`
    // in front, a null read as "nothing to compare against" made the guard PERMISSIVE at exactly
    // the moment it was most needed — every case-scoped state would have painted onto a dashboard
    // the analyst had just emptied. A state carrying no caseId at all is still rendered; only a
    // state that names a case nobody is looking at is dropped.
    if (rawState && rawState.caseId && rawState.caseId !== activeCaseId) return;
    // Keep the raw state FIRST — this is the page's ONLY writer of lastState, and every
    // `if (DfirState.lastState()) render(...)` refresh is a silent no-op until it has run once.
    DfirState.setLastState(rawState);
    if (typeof renderCollectionPlan === "function") renderCollectionPlan(); // fire-and-forget (it reads the plan from the server). Guarded: it ships as its own separate script file, and a ReferenceError here aborted the whole of render() — into a bare `catch {}` on case load and into an uncaught ws.onmessage on every state push.
    const state = DfirScope.project(rawState);
    // The three AI-prose panels — Executive Summary, Attack Path, Narrative Timeline — render
    // through proseHtml (js/dashboard-fragments.js): escaped paragraphs inside a .prose container,
    // rather than one unbroken block of text at full page width. The RAW text stays on the element
    // as data-raw because the narrative editor loads it back into its textarea, and reading
    // .textContent off the paragraphs would silently drop every paragraph break the split added.
    document.getElementById("summary").innerHTML = proseHtml(
      state.lastSummary || "—",
    );
    document.getElementById("attackerPath").innerHTML = proseHtml(
      state.attackerPath || "—",
    );
    const narrative = state.narrativeTimeline || "—";
    const narrativeView = document.getElementById("narrativeView");
    narrativeView.dataset.raw = narrative;
    narrativeView.innerHTML = proseHtml(narrative);

    const PRIO = {
      critical: "#ff5c5c",
      high: "#ff9f43",
      medium: "#ffd93b",
      low: "#6bcB77",
    };

    // Structured collection directives (investigation-guidance #8, phase 3): render a one-click
    // Deploy for a collect target on a KNOWN case host when Velociraptor is configured, else a
    // copyable manual-collection line. Host is matched on its short name (mirrors the server's
    // shortHost) against the case's observed assets, so a hallucinated hostname never gets a button.
    const shortHostJs = (v) =>
      String(v || "")
        .toLowerCase()
        .replace(/^https?:\/\//, "")
        .split(/[\/:?]/)[0]
        .split(".")[0];
    const knownHostKeys = new Set(
      (state.forensicTimeline || [])
        .map((e) => shortHostJs(e.asset))
        .filter(Boolean),
    );
    const collectDirectiveHtml = (c) => {
      if (!c || !c.host) return "";
      const what = c.logSource || c.artifact || "";
      const summary =
        `collect ${esc(what)}${what ? " " : ""}from ${esc(c.host)}` +
        (c.expectedOutcome ? ` — expected: ${esc(c.expectedOutcome)}` : "");
      const deployable = veloEnabled && knownHostKeys.has(shortHostJs(c.host));
      const btn = deployable
        ? `<button class="collect-deploy" data-host="${escAttr(c.host)}" data-artifact="${escAttr(c.artifact || "")}" data-logsource="${escAttr(c.logSource || "")}" title="Launch this collection on ${escAttr(c.host)} via Velociraptor">⬇ Collect on ${esc(c.host)}</button>`
        : `<span class="collect-manual" title="${veloEnabled ? "Host not seen in this case — collect manually" : "Velociraptor API not configured — collect manually"}">manual collection</span>`;
      return `<span class="collect-directive"><span class="collect-what">📥 ${summary}</span> ${btn}</span>`;
    };

    const ns = state.nextSteps || [];
    document.getElementById("nextSteps").innerHTML = ns.length
      ? ns
          .map((s) => {
            const color = PRIO[s.priority] || "#9aa4b2";
            return (
              `<div class="step-row" data-safe-style="--step-color:${color}">` +
              `<span class="step-priority">${esc(String(s.priority || "").toUpperCase())}</span> ${esc(s.action)}` +
              // Immediate FP cascade (#12): this step advanced a finding just marked false positive.
              (s.staleReSynth
                ? ` <span class="stale-badge" title="A finding this step relied on was marked false positive — re-synthesis is queued to refresh it.">⏳ stale — re-synthesis queued</span>`
                : "") +
              (s.rationale
                ? `<span class="step-rationale">${esc(s.rationale)}</span>`
                : "") +
              (s.pointer
                ? `<span class="step-pointer">→ ${esc(s.pointer)}</span>`
                : "") +
              collectDirectiveHtml(s.collect) +
              `</div>`
            );
          })
          .join("")
      : "<div data-safe-style='color:var(--text-muted)'>Not assessed yet — run Synthesize.</div>";

    const QSTATUS = {
      answered: "Answered",
      partial: "Partial",
      unknown: "Unknown",
    };
    const kq = state.keyQuestions || [];
    document.getElementById("keyQuestions").innerHTML = kq.length
      ? kq
          .map((q) => {
            const st = QSTATUS[q.status] ? q.status : "unknown";
            return (
              `<div class="qrow" data-question-id="${escAttr(q.id)}">` +
              `<div class="q-head">${commentChip("question", q.id)} ${tagChip("question", q.id)}` +
              (q.pinned
                ? ` <span class="icon-pinned" title="Pinned">${ICON_PIN}</span>`
                : "") +
              ` <span class="q-status q-status-${st}">${QSTATUS[st]}</span> <strong>${esc(q.question)}</strong>` +
              // Immediate FP cascade (#12): a finding that backed this answer was just marked false
              // positive; the answer was neutralized now and re-synthesis is queued to recompute it.
              (q.staleReSynth
                ? ` <span class="stale-badge" title="A finding this answer relied on was marked false positive — this answer was cleared and re-synthesis is queued.">⏳ stale — re-synthesis queued</span>`
                : "") +
              `</div>` +
              `<span class="q-answer">${esc(q.answer || "unknown")}</span>` +
              // Contradiction badge (investigation-guidance #3): the negative answer conflicts with
              // ATT&CK-tagged events in the timeline — flag it so a wrong "no" is never read as settled.
              (q.contradicted &&
              q.contradicted.techniques &&
              q.contradicted.techniques.length
                ? ` <span class="q-contradicted" data-safe-style="color:var(--badge-danger-text);font-weight:600" title="The timeline contains events tagged ${esc(q.contradicted.techniques.join(", "))} that contradict this negative answer — review before concluding.">⚠️ contradicted by timeline (${esc(q.contradicted.techniques.join(", "))})</span>`
                : "") +
              (q.pointer
                ? `<span class="q-pointer">→ ${esc(q.pointer)}</span>`
                : "") +
              (q.status !== "answered" ? collectDirectiveHtml(q.collect) : "") +
              `</div>`
            );
          })
          .join("")
      : "<div data-safe-style='color:var(--text-muted)'>Not assessed yet — run Synthesize.</div>";

    // Uncertainty ledger (#73): analytical-safety separation of known / inferred / speculated /
    // unknown, so an inferred conclusion is never read as a confirmed fact. Weakest status first —
    // speculated/unknown surface at the top where the open risk is.
    const UNC_META = {
      confirmed: {
        label: "Confirmed",
        color: "#6bcb77",
        desc: "directly evidenced",
      },
      inferred: {
        label: "Inferred",
        color: "#ffd93b",
        desc: "deduced from indirect evidence",
      },
      speculated: {
        label: "Speculated",
        color: "#ff9f43",
        desc: "plausible guess, little evidence",
      },
      unknown: { label: "Unknown", color: "#9aa4b2", desc: "no basis yet" },
    };
    const UNC_ORDER = { speculated: 0, unknown: 1, inferred: 2, confirmed: 3 };
    const unc = (state.uncertainties || [])
      .slice()
      .sort((a, b) => (UNC_ORDER[a.status] ?? 9) - (UNC_ORDER[b.status] ?? 9));
    document.getElementById("uncertainties").innerHTML = unc.length
      ? unc
          .map((u) => {
            const m = UNC_META[u.status] || UNC_META.unknown;
            return (
              `<div class="step-row" data-safe-style="--step-color:${m.color}">` +
              `<span class="step-priority" title="${esc(m.desc)}">${esc(m.label)}</span> <strong>${esc(u.topic)}</strong>` +
              (u.basis
                ? `<span class="step-rationale">Basis: ${esc(u.basis)}</span>`
                : "") +
              (u.gap
                ? `<span class="step-pointer">Gap → ${esc(u.gap)}</span>`
                : "") +
              `</div>`
            );
          })
          .join("")
      : "<div data-safe-style='color:var(--text-muted)'>Not assessed yet — run Synthesize.</div>";

    renderIocs(state.iocs || []);
    lastIocs = state.iocs || [];

    // Already scope-projected above (events + findings/IOCs/MITRE consistently).
    // Then hide events the client confirmed as a false positive (preserved in state; just
    // not shown here and excluded from synthesis — un-mark restores them).
    const fpIds = fpEventIdSet();
    const ft = (state.forensicTimeline || []).filter(
      (e) => !fpIds.has(String(e.id).trim().toLowerCase()),
    );
    // Aggregate each finding's evidence from the events that back it: synthesis-made
    // findings carry no sourceScreenshots themselves, but their events do.
    const evByFinding = {};
    const suppEventsByFinding = {}; // finding id -> the forensic events that back it (for the support rows)
    for (const e of ft) {
      for (const fid of e.relatedFindingIds || []) {
        (evByFinding[fid] = evByFinding[fid] || []).push(
          ...(e.sourceScreenshots || []),
        );
        (suppEventsByFinding[fid] = suppEventsByFinding[fid] || []).push(e);
      }
    }
    DfirState.setLastFt(ft);
    renderTimelineEvents(ft);
    renderKillChain(ft);
    toggleMemNextSteps(ft); // show the Memory Next Steps panel only when Volatility/Rekall evidence exists (#101)
    if (typeof hasPhases === "function" && hasPhases()) renderPhases(); // refresh expansion details against the new timeline

    const openThreads = state.openThreads.filter((t) => t.status === "open");
    const closedThreads = state.openThreads.filter(
      (t) => t.status === "closed",
    );
    document.getElementById("openThreads").innerHTML =
      openThreads
        .map(
          (t) =>
            `<div class="thread-row"><span class="thread-dot thread-dot-open"></span>${commentChip("thread", t.id)} ${tagChip("thread", t.id)} <span class="thread-id">${esc(t.id)}</span> ${esc(t.description)}</div>`,
        )
        .join("") ||
      "<div data-safe-style='color:var(--text-muted)'>No open threads</div>";
    document.getElementById("closedThreads").innerHTML = closedThreads.length
      ? `<div data-safe-style='margin-top:8px;color:var(--sev-low)'>Closed (${closedThreads.length}):</div>` +
        closedThreads
          .map(
            (t) =>
              `<div class="thread-row thread-row-closed"><span class="thread-dot thread-dot-closed"></span><span class="thread-id">${esc(t.id)}</span> ${esc(t.description)}</div>`,
          )
          .join("")
      : "";
    // Drop findings just confirmed false-positive immediately, client-side — don't wait for the
    // background AI re-synthesis (which can take many seconds) to actually remove them from state.
    const fpFindingTitles = fpFindingTitleSet();
    const notFp = fpFindingTitles.size
      ? (state.findings || []).filter(
          (f) => !isFindingFalsePositive(f.title, fpFindingTitles),
        )
      : state.findings || [];
    // Rabbit-hole grouping (investigation-guidance #13): leads (connected/undetermined) first, then
    // Parked (unrelated-but-real), then Possible rabbit holes (disconnected) — so guidance sinks
    // findings with no causal link to the attack path below the real leads. Severity orders within each.
    const relRank = (f) =>
      f.relevance === "disconnected"
        ? 2
        : f.relevance === "unrelated-but-real"
          ? 1
          : 0;
    const sorted = [...notFp].sort(
      (a, b) =>
        relRank(a) - relRank(b) ||
        SEV.indexOf(a.severity) - SEV.indexOf(b.severity),
    );
    const minConf =
      parseInt(document.getElementById("confFilter").value, 10) || 0;
    // Finding-origin lenses: hide the deterministic backfills (f-auto-*, f-gap-*) so the panel
    // shows only what AI synthesis concluded. Read once per render, like minConf above.
    const hideAuto = document.getElementById("hideAutoFindings").checked;
    const hideGap = document.getElementById("hideGapFindings").checked;
    const activeDashView = DfirState.activeView(); // read once; this function consults it three times
    // Corroboration lens (#35): a finding's sources are the union of its supporting events' tools.
    const _findingCorrob = (f) => {
      if (DfirTimelineView.corrobFindings() <= 1) return true;
      const srcs = new Set();
      for (const e of suppEventsByFinding[f.id] || [])
        for (const s of e.sources || [])
          if (s && s !== "unknown source") srcs.add(s);
      return srcs.size >= DfirTimelineView.corrobFindings();
    };
    const filtered = sorted.filter(
      (f) =>
        (f.confidence === undefined || f.confidence >= minConf) &&
        (!DfirTimelineView.search() ||
          _findingMatchesSearch(f, DfirTimelineView.search())) &&
        !(
          DfirTimelineView.excludeTerms().length &&
          _findingMatchesExclude(f, DfirTimelineView.excludeTerms())
        ) &&
        _findingCorrob(f) &&
        findingPassesOriginLens(f, hideAuto, hideGap) &&
        viewMeetsMinSev(f.severity),
    ); // dashboard-view severity floor (#142)
    const capped = viewTopN() > 0 ? filtered.slice(0, viewTopN()) : filtered; // view top-N cap
    // Findings count in the title bar — mirrors the timeline's count: total in scope, "N of M" when filtered.
    const findingsCountEl = document.getElementById("findingsCount");
    if (findingsCountEl) {
      const totalFindings = sorted.length;
      const shownFindings = capped.length;
      const findingsFiltering =
        minConf > 0 ||
        !!DfirTimelineView.search() ||
        DfirTimelineView.excludeTerms().length > 0 ||
        DfirTimelineView.corrobFindings() > 1 ||
        hideAuto ||
        hideGap ||
        !!(
          activeDashView &&
          activeDashView.filters &&
          (activeDashView.filters.minSeverity || viewTopN())
        );
      findingsCountEl.textContent = findingsFiltering
        ? `(${shownFindings} of ${totalFindings} findings)`
        : `(${totalFindings} finding${totalFindings !== 1 ? "s" : ""})`;
    }
    const findingAllIds = capped.map((f) => f.id);
    const findingAllSel =
      findingAllIds.length > 0 &&
      findingAllIds.every((id) => DfirSelection.findings.has(id));
    const findingSomeSel = findingAllIds.some((id) =>
      DfirSelection.findings.has(id),
    );
    const findingHeaderRow = capped.length
      ? `<div class="finding-header-row">` +
        `<span data-safe-style="grid-column:1/3;display:flex;align-items:center;gap:6px">` +
        `<input type="checkbox" class="finding-cb" id="findingSelectAll" ${findingAllSel ? "checked" : ""} title="Select / deselect all visible findings" /> Select all` +
        `</span>` +
        `<span>Severity</span><span>ID</span><span>Finding</span><span>Confidence</span><span></span>` +
        `</div>`
      : "";
    document.getElementById("findings").innerHTML =
      findingHeaderRow +
        capped
          .map((f) => {
            const evidence = [
              ...(f.sourceScreenshots || []),
              ...(evByFinding[f.id] || []),
            ];
            // Citations (#222): prefer the finding's own relatedEventIds (set by synthesis); fall back
            // to the events that back-link to it via relatedFindingIds for findings persisted before
            // this field existed, so nothing regresses.
            const citeIds =
              f.relatedEventIds && f.relatedEventIds.length
                ? f.relatedEventIds
                : (suppEventsByFinding[f.id] || []).map((e) => e.id);
            // Auto-flagged findings (from a Critical/High artifact row synthesis didn't cover)
            // carry the f-auto- id prefix — badge them so the analyst knows to review/refine. Same
            // predicate the origin lens above uses (isAutoBackfillFinding, dashboard-filters.js)
            // rather than a second f-auto- check of its own — two classifiers for one prefix is how
            // the badge and the lens end up disagreeing if that prefix ever changes.
            const auto = isAutoBackfillFinding(f)
              ? ` <span title="Auto-flagged from a ${esc(f.severity)}-severity artifact row — review and refine" data-safe-style="background:var(--info-bg);color:var(--tag-purple-text);border:1px solid var(--info-border);border-radius:4px;padding:0 6px;font-size:10px">AUTO</span>`
              : "";
            // Confidence meter: same high/mid/low tiering as the old badge, now a small bar + %.
            let confMeter = "";
            if (f.confidence !== undefined) {
              const cls =
                f.confidence >= 80
                  ? "conf-high"
                  : f.confidence >= 50
                    ? "conf-mid"
                    : "conf-low";
              const barColor =
                cls === "conf-high"
                  ? "var(--sev-low)"
                  : cls === "conf-mid"
                    ? "var(--help-icon-color)"
                    : "var(--badge-danger-text)";
              const confTitle =
                `AI confidence: ${f.confidence}%` +
                (f.confidenceReason ? ` — ${f.confidenceReason}` : "");
              confMeter = `<span class="fcbar" title="${escAttr(confTitle)}"><span data-safe-style="width:${f.confidence}%;background:${barColor}"></span></span><span class="fcpct">${f.confidence}%</span>`;
            }
            const isSelFinding = DfirSelection.findings.has(f.id);
            const evidenceBody = findingEvidenceDetails(
              f,
              state.caseId,
              evidence,
              suppEventsByFinding[f.id] || [],
              state.iocs,
              citeIds,
            );
            const hasEvidence = !!evidenceBody;
            // A plain <button>, not a native <summary> — <details> hides ALL non-summary children
            // (via content-visibility, not a simple display:none you can override) whenever it's
            // closed, which would blank out the checkbox/severity/id/title too, not just the
            // evidence panel. Toggling is handled by the delegated .finding-chevron click handler.
            const chevron =
              `<button type="button" class="finding-chevron" data-fev-toggle="${escAttr(f.id)}" title="Expand evidence"${hasEvidence ? "" : " disabled"}>` +
              `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 3l5 5-5 5"/></svg></button>`;
            const tagPillsHtml = tagPills("finding", f.id);
            // Rabbit-hole detection (investigation-guidance #13): a chip that names the finding's relation
            // to the main attack path. 'disconnected' = possible rabbit hole (with the "look for" chip);
            // 'unrelated-but-real' = parked (a genuine but separate issue). Leads carry no chip (default).
            let relChip = "";
            if (f.relevance === "disconnected") {
              relChip = ` <span class="rel-chip rel-rabbit" title="${escAttr(f.relevanceDiscriminator || "No causal link to the main attack path — verify before chasing.")}">🕳️ possible rabbit hole — verify before chasing</span>`;
            } else if (f.relevance === "unrelated-but-real") {
              relChip = ` <span class="rel-chip rel-parked" title="Genuine activity, but not part of this incident's attack path — parked.">🅿️ parked — real but unrelated</span>`;
            }
            return (
              `<div class="finding${isSelFinding ? " finding-selected" : ""}" data-fid="${escAttr(f.id)}">` +
              chevron +
              `<input type="checkbox" class="finding-cb finding-row-cb" data-fid="${escAttr(f.id)}" ${isSelFinding ? "checked" : ""} title="Select finding" />` +
              `<span class="finding-sev-cell sev-${esc(f.severity)}"><span class="fsq"></span>${esc(f.severity)}</span>` +
              `<span class="finding-id-cell" title="${escAttr(f.id)}">${esc(f.id)}</span>` +
              `<span class="finding-main-cell">` +
              `<span class="finding-title"><strong>${esc(f.title)}</strong>${auto}${relChip}</span>` +
              `<span class="finding-desc" title="${escAttr(f.description)}">${esc(f.description)}</span>` +
              (tagPillsHtml
                ? `<span class="finding-tagline">${tagPillsHtml}</span>`
                : "") +
              `</span>` +
              `<span class="finding-conf-cell">${confMeter}</span>` +
              `<span class="finding-actions-cell">${findingWorkflowControls(f.id)} ${commentChip("finding", f.id)} ${tagAddBtn("finding", f.id)} ${pinBtn(f.id)} ${sigmaExportChip(f.id)} ${ticketPushChips(f.id)} ${fpBtn("finding", f.title)}</span>` +
              (hasEvidence
                ? `<div class="finding-evidence-body" id="fev-${escAttr(f.id)}">${evidenceBody}</div>`
                : "") +
              `</div>`
            );
          })
          .join("") ||
      (DfirTimelineView.search() && sorted.length > 0
        ? `<span data-safe-style="color:var(--text-muted)">No findings match the filter.</span>`
        : minConf > 0 && sorted.length > 0
          ? `<span data-safe-style="color:var(--text-muted)">No findings above ${minConf}% confidence.</span>`
          : activeDashView &&
              (viewFilters().minSeverity || viewTopN()) &&
              sorted.length > 0
            ? `<span data-safe-style="color:var(--text-muted)">No findings match the “${esc(activeDashView.name)}” view filter.</span>`
            : "—");
    const findingSelAllEl = document.getElementById("findingSelectAll");
    if (findingSelAllEl && findingSomeSel && !findingAllSel)
      findingSelAllEl.indeterminate = true;
    updateFindingBulkBar();
    // Investigation Log = state.timeline (import / AI notes) + analyst quick-action audit lines
    // (durable comments tagged with the quick-actions audit mark), merged chronologically.
    // The literal fallback is deliberate: if dashboard-ioc-quick-actions.js fails to load the
    // buttons go away, but audit lines already in the case must still show up here.
    const _auditMark =
      (typeof qaAuditMark === "function" ? qaAuditMark() : null) || "⚑";
    const _logRows = state.timeline.map((t) => ({
      ts: t.timestamp,
      html: esc(t.description),
    }));
    eachCommentList((list) =>
      list.forEach((c) => {
        if (typeof c.text === "string" && c.text.indexOf(_auditMark) === 0) {
          const who = c.author
            ? ` <span data-safe-style="color:var(--text-muted)">— ${esc(c.author)}</span>`
            : "";
          _logRows.push({ ts: c.createdAt, html: esc(c.text) + who });
        }
      }),
    );
    _logRows.sort((a, b) => String(a.ts).localeCompare(String(b.ts)));
    document.getElementById("timeline").innerHTML =
      _logRows
        .map(
          (r) =>
            `<div class="log-row"><span class="log-time">${esc(r.ts)}</span><span>${r.html}</span></div>`,
        )
        .join("") || "—";
    document.getElementById("mitre").innerHTML =
      state.mitreTechniques
        .map(
          (m) =>
            `<div class="mitre-row">${mitreLinks([m.id])} <span>${esc(m.name)}</span><span class="mitre-findings">${esc(m.findingIds.join(", "))}</span></div>`,
        )
        .join("") || "—";
    renderPinned(); // pinned-strip titles resolve against the just-rendered findings (#220)
  }

  window.render = render;
})();
