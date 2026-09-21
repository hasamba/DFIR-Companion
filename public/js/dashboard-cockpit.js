// "Now" investigator cockpit (#375) — extracted from dashboard.html (issue #415, tier 3).
//
// Third block freed by correctly measuring the spine. Its 440-line banner read as core machinery
// because render() — 251 lines, the page's central redraw — sat at the end of it. The cockpit
// itself is 187 lines with zero escapes, and was untouchable only by association.
//
// render() stays in the page under its own banner. It is called from the state path, the websocket
// handler and a dozen features; moving it is a different change from moving features out, and one
// that needs a decision rather than a recipe.
(function () {
  "use strict";

  // The server composes this from the case's existing findings, hypotheses, contradictions,
  // collection directives, jobs and change metadata. Rendering stays deliberately dumb: no
  // client-side scoring that could disagree between investigators.
  const COCKPIT_GROUPS = [
    [
      "leads",
      "Active leads",
      "No active leads yet — import or assess evidence to establish one.",
      true,
    ],
    [
      "changes",
      "Since your last review",
      "Nothing new since your last review.",
      true,
    ],
    [
      "hypotheses",
      "Open hypotheses",
      "No open hypotheses need attention.",
      false,
    ],
    [
      "steps",
      "Next recommended step",
      "No recommended step yet — synthesis writes the playbook after each import.",
      false,
    ],
    [
      "contradictions",
      "Contradictions & uncertainty",
      "No material contradictions are currently recorded.",
      false,
    ],
    [
      "gaps",
      "Evidence gaps & next collections",
      "No outstanding collection gap is recorded.",
      true,
    ],
    [
      "activity",
      "Running / failed work",
      "No imports or analyses are running or failed.",
      false,
    ],
    [
      "blockers",
      "Report-readiness blockers",
      "The case is ready for report preparation.",
      true,
    ],
  ];

  function cockpitGroupHtml(key, label, empty, wide) {
    const cards =
      (lastCockpit && lastCockpit.sections && lastCockpit.sections[key]) || [];
    const ready =
      key === "blockers" &&
      lastCockpit &&
      lastCockpit.readiness &&
      lastCockpit.readiness.ready;
    const body = cards.length
      ? cards.map((card) => cockpitCardHtml(card, false)).join("")
      : ready
        ? `<div class="now-ready">✓ ${esc(empty)}</div>`
        : `<div class="now-empty">${esc(empty)}</div>`;
    return `<div class="now-group${wide ? " now-wide" : ""}"><div class="now-group-head">${esc(label)}<span class="now-group-count">${cards.length}</span></div>${body}</div>`;
  }

  // "Story so far" (#1487): the attack chain at one glance, above the workspaces row. The server
  // derives it from the forensic timeline only (never the super-timeline) and trims the synthesis
  // prose to two sentences; the client formats and escapes, nothing more.
  const STORY_EMPTY_CHAIN =
    "No staged activity yet — import evidence to build the chain.";
  const STORY_EMPTY_TEXT =
    "No synthesis yet — the conclusion appears after the first analysis run.";

  function storyStageMs(stage) {
    const t = Date.parse(stage && stage.firstSeenAt);
    return Number.isFinite(t) ? t : null;
  }

  // `HH:MM` while every stage sits on one UTC day, `MM-DD HH:MM` once the chain spans days. Always
  // UTC — the timeline is UTC, and a chip that disagrees with the row it filters to is a trap.
  function storyStageTime(ms, withDay) {
    if (ms === null) return "—";
    const iso = new Date(ms).toISOString();
    const clock = iso.slice(11, 16);
    return withDay ? `${iso.slice(5, 10)} ${clock}` : clock;
  }

  function storySpansDays(stages) {
    const days = new Set(
      stages
        .map(storyStageMs)
        .filter((ms) => ms !== null)
        .map((ms) => new Date(ms).toISOString().slice(0, 10)),
    );
    return days.size > 1;
  }

  function storyFreshness(story) {
    if (!story.synthesizedAt) return { text: "no synthesis yet", stale: false };
    const n = story.staleEventCount || 0;
    if (n > 0)
      return {
        text: `stale — ${n} event${n === 1 ? "" : "s"} since synthesis`,
        stale: true,
      };
    return { text: `synthesis ${cockpitAge(story.synthesizedAt)}`, stale: false };
  }

  function storyStageHtml(stage, withDay) {
    const meta = [storyStageTime(storyStageMs(stage), withDay)];
    if (stage.host) meta.push(stage.host);
    meta.push(`${stage.eventCount || 0} ev`);
    return (
      `<button data-act="cockpitStoryStage" data-tactic="${escAttr(stage.tactic)}" class="now-stage">` +
      `<span class="now-stage-name">${esc(stage.tactic)}</span>` +
      `<span class="now-stage-meta">${esc(meta.join(" · "))}</span></button>`
    );
  }

  function storyChainHtml(stages) {
    if (!stages.length) return `<div class="now-empty">${esc(STORY_EMPTY_CHAIN)}</div>`;
    const withDay = storySpansDays(stages);
    return `<div class="now-story-chain">${stages
      .map((stage) => storyStageHtml(stage, withDay))
      .join(`<span class="now-stage-arrow">▶</span>`)}</div>`;
  }

  function storyTextHtml(story) {
    if (!story.synthesizedAt)
      return `<div class="now-empty">${esc(STORY_EMPTY_TEXT)}</div>`;
    const conclusion = story.conclusion
      ? `<p>${esc(story.conclusion)}</p>`
      : "";
    const path = story.attackerPath ? `${esc(story.attackerPath)} ` : "";
    return (
      `<div class="now-story-text">${conclusion}<p>${path}` +
      `<button data-act="cockpitStoryOpen" data-panel="attack-path">Full path ↗</button> ` +
      `<button data-act="cockpitStoryOpen" data-panel="summary">Executive summary ↗</button></p></div>`
    );
  }

  // Empty string on an old server whose snapshot has no `story`, so the rest of the cockpit still
  // paints.
  function cockpitStoryHtml(story) {
    if (!story) return "";
    const fresh = storyFreshness(story);
    const freshClass = fresh.stale
      ? "now-story-fresh now-story-stale"
      : "now-story-fresh";
    return (
      `<div class="now-story"><div class="now-story-head">Story so far ` +
      `<span class="${freshClass}">${esc(fresh.text)}</span></div>` +
      `${storyChainHtml(story.stages || [])}${storyTextHtml(story)}</div>`
    );
  }

  function renderCockpit(snapshot) {
    const { generatedAt: _generatedAt, ...stableSnapshot } = snapshot;
    const signature = JSON.stringify(stableSnapshot);
    const unchanged =
      lastCockpit &&
      lastCockpit.caseId === snapshot.caseId &&
      signature === lastCockpitRenderSignature;
    lastCockpit = snapshot;
    if (unchanged) return;
    lastCockpitRenderSignature = signature;
    const body = document.getElementById("cockpitBody");
    const phase = document.getElementById("cockpitPhase");
    const reviewMeta = document.getElementById("cockpitReviewMeta");
    if (!body || !snapshot) return;
    const friendlyPhase =
      {
        triage: "Triage",
        "active-investigation": "Active investigation",
        "report-preparation": "Report preparation",
      }[snapshot.phase] || snapshot.phase;
    if (phase) phase.textContent = friendlyPhase;
    if (reviewMeta) {
      const reviewed = snapshot.lastReviewedAt
        ? `last reviewed ${cockpitAge(snapshot.lastReviewedAt)}`
        : "not reviewed yet";
      reviewMeta.textContent = `${snapshot.newSinceReview || 0} new · ${reviewed} · ${snapshot.investigator || "analyst"}`;
    }
    const groups = COCKPIT_GROUPS.map((args) => cockpitGroupHtml(...args)).join(
      "",
    );
    const parked = (snapshot.parked || []).length
      ? `<div class="now-group now-wide now-parked"><div class="now-group-head">Dismissed / deferred<span class="now-group-count">${snapshot.parked.length}</span></div>${snapshot.parked.map((card) => cockpitCardHtml(card, true)).join("")}</div>`
      : "";
    const workspaces =
      `<div class="now-workspaces"><span>Focused workspaces:</span>` +
      `<button data-act="cockpitWorkspace" data-view="triage" data-panel="sec-timeline">Timeline</button>` +
      `<button data-act="cockpitWorkspace" data-view="hunt-prep" data-panel="sec-playbook">Hunt</button>` +
      `<button data-act="cockpitWorkspace" data-view="deep-dive" data-panel="sec-evidence">Evidence</button>` +
      `<button data-act="cockpitWorkspace" data-view="hunt-prep" data-panel="sec-iocs">Intelligence</button>` +
      `<button data-act="cockpitWorkspace" data-view="report" data-panel="sec-exec">Report</button></div>`;
    body.innerHTML = `${cockpitStoryHtml(snapshot.story)}${workspaces}<div class="now-grid">${groups}${parked}</div>`;
  }

  async function loadCockpit(caseId) {
    caseId = caseId || document.getElementById("caseId").value.trim();
    const body = document.getElementById("cockpitBody");
    if (!caseId || !body) return;
    const hasCurrentSnapshot = lastCockpit && lastCockpit.caseId === caseId;
    if (!hasCurrentSnapshot)
      body.innerHTML = `<div class="now-state">Loading the current decisions…</div>`;
    const investigator = investigatorName();
    try {
      const query = investigator
        ? `?investigator=${encodeURIComponent(investigator)}`
        : "";
      const response = await fetch(
        `/cases/${encodeURIComponent(caseId)}/cockpit${query}`,
      );
      const payload = await response.json().catch(() => ({}));
      if (!response.ok)
        throw new Error(payload.error || `HTTP ${response.status}`);
      if (caseId !== document.getElementById("caseId").value.trim()) return;
      renderCockpit(payload);
    } catch (err) {
      if (caseId !== document.getElementById("caseId").value.trim()) return;
      if (!hasCurrentSnapshot) {
        body.innerHTML = `<div class="now-state"><strong>Cockpit could not load.</strong> ${esc(err.message || "Unknown error")} <button data-act="cockpitRetry">Retry</button><br><span>Use Import evidence, Findings, Jobs and Report workspaces directly while this is unavailable.</span></div>`;
      } else {
        console.warn(
          "Cockpit refresh failed; keeping the last stable view:",
          err,
        );
      }
    }
  }

  async function cockpitAction(el) {
    const caseId = document.getElementById("caseId").value.trim();
    const cardId = el.dataset.id;
    const action = el.dataset.cockpitAction;
    if (!caseId || !cardId || !action) return;
    let value = "";
    if (
      action === "dismiss" &&
      !confirm(
        "Dismiss this cockpit card? The action remains in the audit history and can be restored from the parked section.",
      )
    )
      return;
    if (action === "defer") {
      const tomorrow = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      value =
        prompt("Defer until (date/time or ISO timestamp):", tomorrow) || "";
      if (!value) return;
    }
    if (action === "assign") {
      const assignee = prompt("Assign this lead to:", "");
      if (assignee === null) return;
      value = assignee;
    }
    el.disabled = true;
    try {
      const response = await fetch(
        `/cases/${encodeURIComponent(caseId)}/cockpit/cards/${encodeURIComponent(cardId)}`,
        {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ action, actor: investigatorName(), value }),
        },
      );
      const payload = await response.json().catch(() => ({}));
      if (!response.ok)
        throw new Error(payload.error || `HTTP ${response.status}`);
      await loadCockpit(caseId);
      if (action === "pin" || action === "unpin") loadPins(caseId);
      if (action === "assign") {
        loadFindingWorkflow(caseId);
        loadHypotheses(caseId);
      }
    } catch (err) {
      alert(`Cockpit action failed: ${err.message}`);
      el.disabled = false;
    }
  }

  // Cockpit panel key → the view that shows it and the section to reveal. One table for the card
  // targets (cockpitOpenTarget) and the story links (cockpitStoryOpen), so the two cannot drift.
  const COCKPIT_PANELS = {
    findings: ["lead", "sec-findings"],
    hypotheses: ["deep-dive", "sec-hypotheses"],
    questions: ["lead", "sec-questions"],
    uncertainties: ["deep-dive", "sec-uncertainties"],
    timeline: ["triage", "sec-timeline"],
    playbook: ["hunt-prep", "sec-playbook"],
    "super-timeline": ["deep-dive", "sec-super-timeline"],
    summary: ["lead", "sec-exec"],
    "attack-path": ["lead", "sec-attack-path"],
    report: ["report", "sec-case-details"],
  };

  function cockpitRevealPanel(panelKey) {
    const [viewId, sectionId] = COCKPIT_PANELS[panelKey] || [];
    const view = DASHBOARD_VIEWS.find((item) => item.id === viewId);
    if (view) applyDashboardView(view, { persist: true, rerender: true });
    if (sectionId) setTimeout(() => revealSection(sectionId), 0);
  }

  function cockpitOpenTarget(el) {
    if (!lastCockpit) return;
    const cards = [
      ...Object.values(lastCockpit.sections || {}).flat(),
      ...(lastCockpit.parked || []),
    ];
    const card = cards.find((item) => item.id === el.dataset.id);
    if (!card || !card.target) return;
    const target = card.target;
    if (target.panel === "import") {
      document.getElementById("importBtn").click();
      return;
    }
    if (target.panel === "jobs") {
      document.getElementById("jobsBadge").click();
      return;
    }
    // Deliberately NOT in COCKPIT_PANELS: those entries switch the analyst into
    // another view first, and the duplicate-host panel is reachable from the one they are already
    // in — it is data-gated, and its own module opens the gate. Sending them to Analyst to answer a
    // yes/no question would throw away the cockpit they are working in.
    if (target.panel === "host-duplicates") {
      revealHostDuplicates();
      return;
    }
    cockpitRevealPanel(target.panel);
    if (target.findingId) setTimeout(() => jumpToFinding(target.findingId), 0);
    else if (target.hypothesisId)
      setTimeout(() => jumpToHypothesis(target.hypothesisId), 0);
    else if (target.questionId)
      setTimeout(() => jumpToQuestion(target.questionId), 0);
    else if (target.eventId) setTimeout(() => jumpToEvent(target.eventId), 0);
  }

  // A story chip filters the forensic timeline to exactly that stage's events. The section is
  // revealed first so a profile that hides the timeline still shows the filtered rows.
  function cockpitStoryStage(el) {
    const stages =
      (lastCockpit && lastCockpit.story && lastCockpit.story.stages) || [];
    const stage = stages.find((item) => item.tactic === el.dataset.tactic);
    if (!stage || !(stage.eventIds || []).length) return;
    revealSection("sec-timeline");
    filterTimelineToEventIds(stage.eventIds, `${stage.tactic} stage`);
  }

  function cockpitStoryOpen(el) {
    cockpitRevealPanel(el.dataset.panel);
  }

  function cockpitWorkspace(el) {
    const view = DASHBOARD_VIEWS.find((item) => item.id === el.dataset.view);
    if (view) applyDashboardView(view, { persist: true, rerender: true });
    if (el.dataset.panel) setTimeout(() => revealSection(el.dataset.panel), 0);
  }

  function cockpitJumpEvent(eventId) {
    const view = DASHBOARD_VIEWS.find((item) => item.id === "triage");
    if (view) applyDashboardView(view, { persist: true, rerender: true });
    setTimeout(() => jumpToEvent(eventId), 0);
  }

  async function markCockpitReviewed() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const btn = document.getElementById("cockpitReviewBtn");
    btn.disabled = true;
    try {
      const response = await fetch(
        `/cases/${encodeURIComponent(caseId)}/cockpit/review`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ investigator: investigatorName() }),
        },
      );
      const payload = await response.json().catch(() => ({}));
      if (!response.ok)
        throw new Error(payload.error || `HTTP ${response.status}`);
      await loadCockpit(caseId);
    } catch (err) {
      alert(`Could not mark the cockpit reviewed: ${err.message}`);
    } finally {
      btn.disabled = false;
    }
  }

  // Refresh and mark-reviewed. Both bind to markup.
  function initCockpit() {
    document
      .getElementById("cockpitRefreshBtn")
      .addEventListener("click", () => loadCockpit());
    document
      .getElementById("cockpitReviewBtn")
      .addEventListener("click", markCockpitReviewed);
  }

  window.initCockpit = initCockpit;
  window.cockpitAction = cockpitAction;
  window.cockpitJumpEvent = cockpitJumpEvent;
  window.cockpitOpenTarget = cockpitOpenTarget;
  window.cockpitStoryOpen = cockpitStoryOpen;
  window.cockpitStoryStage = cockpitStoryStage;
  window.cockpitWorkspace = cockpitWorkspace;
  window.loadCockpit = loadCockpit;
})();
