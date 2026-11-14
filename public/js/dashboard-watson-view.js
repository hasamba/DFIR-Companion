// Watson's markup: pure HTML builders for the chat turns, the proposals, the Key Questions board and
// the panel shell. No state lives here; dashboard-watson.js owns it and
// calls the published builders by name. Split out so each file stays under 400 lines.
//
// Every model, analyst and evidence string goes through esc()/escAttr() (dashboard-escape.js).
// Actions ride on data-act="watsonAct" + data-w-verb; the CSP bans inline handlers.
(function () {
  const QSTATUS = { answered: "Answered", partial: "Partial", unknown: "Unknown", unanswerable: "Not answerable" };

  function statusBadge(status) {
    const st = QSTATUS[status] ? status : "unknown";
    return `<span class="q-status q-status-${st}">${esc(QSTATUS[st])}</span>`;
  }

  function requestHtml(r) {
    if (!r) return "";
    if (r.kind === "query") {
      return (
        `<div class="watson-req"><div class="watson-lbl">Run this ${esc(r.language)} query</div>` +
        `<pre class="watson-pre">${esc(r.query)}</pre>` +
        `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="copy">Copy</button>` +
        `<div class="watson-why">${esc(r.why)}</div></div>`
      );
    }
    if (r.kind === "velociraptor") {
      const where = r.mode === "hunt" ? "fleet hunt" : `collection on ${r.hostname || "a host"}`;
      return (
        `<div class="watson-req"><div class="watson-lbl">Velociraptor ${esc(where)}: ${esc(r.title)}</div>` +
        `<pre class="watson-pre">${esc(r.vql)}</pre>` +
        `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="copy">Copy</button>` +
        `<div class="watson-why">${esc(r.why)}</div></div>`
      );
    }
    return (
      `<div class="watson-req"><div class="watson-lbl">Import ${esc(r.what)}</div>` +
      `<div class="watson-why">${esc(r.why)}</div></div>`
    );
  }

  const btn = (pid, verb, label) =>
    `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="${verb}" data-pid="${escAttr(pid)}">${label}</button> `;

  // Question proposals keep their phase 1 card here; every other kind is drawn by dashboard-watson-cards.js.
  function proposalHtml(p) {
    if (p.kind !== "question_new" && p.kind !== "question_update") return watsonCardHtml(p);
    const a = p.after || {};
    const verbs =
      p.status === "pending"
        ? btn(p.id, "apply", "Apply") + btn(p.id, "reject", "Reject")
        : p.status === "applied"
          ? btn(p.id, "undo", "Undo")
          : "";
    const title = p.kind === "question_new" ? "New question" : "Question update";
    return (
      `<div class="watson-prop" data-pid="${escAttr(p.id)}">` +
      `<div class="watson-lbl">${esc(title)} · ${esc(p.status)}</div>` +
      `<div><strong>${esc(a.question)}</strong></div>` +
      `<div>${statusBadge(a.status)} ${esc(a.answer || "")}</div>` +
      (a.pointer ? `<div class="watson-why">→ ${esc(a.pointer)}</div>` : "") +
      `<div>${verbs}</div></div>`
    );
  }

  // The answer to a free-form question: badge, answer, where to look, cited events, the add button.
  // citeEvents (dashboard-ioc-provenance.js) escapes the ids and links them to the timeline.
  function answerHtml(t, readOnly) {
    const a = t.answer;
    if (!a) return "";
    const ids = Array.isArray(a.relatedEventIds) ? a.relatedEventIds : [];
    const cited = typeof citeEvents === "function" ? citeEvents(ids) : "";
    const used = !!t.answerProposalId;
    return (
      `<div class="watson-ans"><div>${statusBadge(a.status)} <strong>${esc(a.question)}</strong></div>` +
      `<div>${esc(a.answer || "(no answer)")}</div>` +
      (a.pointer ? `<div class="watson-why">→ where to look: ${esc(a.pointer)}</div>` : "") +
      (cited ? `<div class="watson-why">cited events: ${cited}</div>` : "") +
      (readOnly
        ? ""
        : `<div><button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="addQuestion" data-tid="${escAttr(t.id)}"` +
          ` title="Add this to the case's open Key Investigative Questions, with the pointer"${used ? " disabled" : ""}>` +
          `${used ? "Added to open questions" : "Add to open questions"}</button></div>`) +
      `</div>`
    );
  }

  // What the round could not carry whole. Shown to the analyst, not only told to the model (#452).
  function coverageHtml(c) {
    if (!c) return "";
    const used = Number(c.usedEvents);
    const total = Number(c.eventCount);
    const line = (text) => `<div class="watson-cov">⚠ ${text}</div>`;
    return (
      (Number.isFinite(used) && Number.isFinite(total) && used < total
        ? line(`answered from ${esc(String(used))} of ${esc(String(total))} in-scope events — the timeline was trimmed to fit the model`)
        : "") +
      (c.decisionsTrimmed
        ? line("some of your case decisions — hypotheses, scope, marks, notebook — were trimmed to fit the model")
        : "") +
      (c.headTrimmed ? line("part of the case summary was trimmed to fit the model") : "")
    );
  }

  // #2468: no forensic-timeline events and no findings yet, so an answer would have nothing to read.
  // A count that is only a lower bound is not "zero".
  function caseIsEmpty(st) {
    if (!st || st.forensicTimelineTotalIsLowerBound) return false;
    const events =
      typeof st.forensicTimelineTotal === "number"
        ? st.forensicTimelineTotal
        : Array.isArray(st.forensicTimeline)
          ? st.forensicTimeline.length
          : -1;
    const findings = Array.isArray(st.findings) ? st.findings.length : -1;
    return events === 0 && findings === 0;
  }

  // Watson's Auto listing (a system turn) is drawn as a list.
  const autoList = (t) =>
    t.role === "system" && typeof watsonVeloAutoListHtml === "function" ? watsonVeloAutoListHtml(t.text) : "";

  // readOnly: an older turn paged back from the history file. It shows no proposal or add button.
  function turnHtml(t, proposals, readOnly) {
    const reacted = t.role === "system" && String(t.text).startsWith("Watson reacted to");
    const cls = "watson-turn watson-" + (t.error ? "warn" : t.role) + (reacted ? " watson-reacted" : "");
    const who = t.role === "analyst" ? esc(t.actor || "You") : t.role === "system" ? "System" : "Watson";
    const mine = readOnly ? [] : (t.proposalIds || []).map((id) => proposals.find((p) => p.id === id)).filter(Boolean);
    const props = mine.map(proposalHtml).join("") + watsonWroteHtml(mine);
    return (
      `<div class="${cls}"><div class="watson-who">${who}</div>` +
      (t.workingOn ? `<div class="watson-meta"><b>Working on:</b> ${esc(t.workingOn)}</div>` : "") +
      (autoList(t) || `<div class="watson-text">${esc(t.text)}</div>`) +
      answerHtml(t, readOnly) +
      coverageHtml(t.coverage) +
      (t.learned ? `<div class="watson-meta"><b>Learned:</b> ${esc(t.learned)}</div>` : "") +
      requestHtml(t.request) +
      props +
      `</div>`
    );
  }

  function earlierButtonHtml() {
    return `<div class="watson-earlier"><button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="loadEarlier">Load earlier messages</button></div>`;
  }

  function boardHtml(questions) {
    if (!questions.length) return `<div class="watson-empty">No key questions yet.</div>`;
    return questions
      .map((q) => {
        const dis = q.synthesisDisagrees
          ? `<div class="q-contradicted">Synthesis disagrees: ${esc(q.synthesisDisagrees.status)}` +
            (q.synthesisDisagrees.answer ? ` — ${esc(q.synthesisDisagrees.answer)}` : "") +
            `</div>`
          : "";
        return (
          `<div class="watson-q">${statusBadge(q.status)} <strong>${esc(q.question)}</strong>` +
          `<div>${esc(q.answer || "unknown")}</div>` +
          (q.pointer ? `<div class="watson-why">→ ${esc(q.pointer)}</div>` : "") +
          dis +
          `</div>`
        );
      })
      .join("");
  }

  function composerHtml() {
    return (
      `<div class="watson-composer">` +
      `<textarea class="watson-input" rows="2" placeholder="Ask Watson… (Ctrl+Enter to send)" aria-label="Message Watson"></textarea>` +
      `<div class="watson-paste-box"><textarea class="watson-paste-text" rows="5" placeholder="Paste evidence text here" aria-label="Paste evidence"></textarea>` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="pasteSend">Send paste</button></div>` +
      `<div class="watson-actions">` +
      `<button type="button" data-act="watsonAct" data-w-verb="send">Send</button> ` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="pasteToggle">Paste evidence</button> ` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="attachPick">Attach file</button> ` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="newThread" title="Start a fresh thread: Watson keeps its case memory, the earlier chat stays in the history">↺ New thread</button>` +
      `<input type="file" class="watson-file" data-act="watsonAct" data-act-on="change" data-w-verb="file" accept=".txt,.log,.csv,.tsv,.json,.xml,text/*,application/json,application/xml" />` +
      `</div></div>`
    );
  }

  // One shell for all three states; the panel's classes decide what shows (see dashboard-watson.css).
  function panelHtml() {
    return (
      `<button type="button" class="watson-rail" data-act="watsonAct" data-w-verb="open" aria-expanded="false" aria-label="Open Watson">` +
      `<span class="watson-rail-icon">W</span><span class="watson-dot" data-w="dot"></span><span class="watson-count" data-w="count"></span><span data-w="railmode"></span></button>` +
      `<div class="watson-root watson-body"><div class="watson-head"><strong>Watson</strong><span class="watson-mode" data-w="mode"></span><span data-w="velo"></span>` +
      `<button type="button" class="watson-mini watson-only-open" data-act="watsonAct" data-w-verb="fullScreen" aria-expanded="false" aria-label="Full screen">Full screen</button>` +
      `<button type="button" class="watson-mini watson-only-full" data-act="watsonAct" data-w-verb="exitFullScreen" aria-expanded="true" aria-label="Exit full screen">Exit full screen</button>` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="collapse" aria-expanded="true" aria-label="Collapse Watson">Collapse</button></div>` +
      `<div class="watson-main"><div class="watson-board" data-w="board"></div>` +
      `<div class="watson-chat"><div class="watson-log" data-w="log"></div>` +
      composerHtml() +
      `<div class="watson-foot" data-w="foot"></div></div></div></div>`
    );
  }

  window.watsonTurnHtml = turnHtml;
  window.watsonBoardHtml = boardHtml;
  window.watsonEarlierButtonHtml = earlierButtonHtml;
  window.watsonCaseIsEmpty = caseIsEmpty;
  window.watsonPanelHtml = panelHtml;
})();
