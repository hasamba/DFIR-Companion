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
  // ctx: { questions (the board), addError (the server's refusal of this card's add) }. An answer
  // Watson linked to a key question still on the board names it instead of offering to add it.
  function answerHtml(t, readOnly, ctx) {
    const a = t.answer;
    if (!a) return "";
    const ids = Array.isArray(a.relatedEventIds) ? a.relatedEventIds : [];
    const cited = typeof citeEvents === "function" ? citeEvents(ids) : "";
    const used = !!t.answerProposalId;
    const board = ctx && Array.isArray(ctx.questions) ? ctx.questions : [];
    const linked = a.matchesQuestionId ? board.find((q) => q && q.id === a.matchesQuestionId) : null;
    const err = ctx && ctx.addError ? `<div class="watson-why watson-err">${esc(ctx.addError)}</div>` : "";
    return (
      `<div class="watson-ans"><div>${statusBadge(a.status)} <strong>${esc(a.question)}</strong></div>` +
      `<div>${esc(a.answer || "(no answer)")}</div>` +
      (a.pointer ? `<div class="watson-why">→ where to look: ${esc(a.pointer)}</div>` : "") +
      (cited ? `<div class="watson-why">cited events: ${cited}</div>` : "") +
      (readOnly
        ? ""
        : linked
          ? `<div class="watson-why watson-linked">Key question on the board: ${esc(linked.question)}</div>`
          : `<div><button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="addQuestion" data-tid="${escAttr(t.id)}"` +
          ` title="Add this answer and its pointer to the open Key Investigative Questions of the case"${used ? " disabled" : ""}>` +
          `${used ? "Added to open questions" : "Add to open questions"}</button></div>${err}`) +
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
        ? line(`Watson used ${esc(String(used))} of ${esc(String(total))} in-scope events. The companion cut the timeline to fit the model.`)
        : "") +
      (c.decisionsTrimmed
        ? line("The companion cut some of your case decisions (hypotheses, scope, marks, notebook) to fit the model.")
        : "") +
      (c.headTrimmed ? line("The companion cut part of the case summary to fit the model.") : "")
    );
  }

  // Task 11: the forensic-timeline events Watson looked up for this answer. Server-set (never from the
  // model's text), shown on its own line so the analyst sees everything Watson read (#452).
  const fmt = (n) => Number(n).toLocaleString("en-US");

  // One wording per lookup kind, for old and new turns (a turn from before tool mode has one `lookedUp`).
  // Every string comes from the server and goes through esc(). The match count of a super-timeline
  // search may be a floor, and its size limit may have hidden rows.
  const LOOKUP_WHERE = new Map([
    ["supertimeline", ["Watson searched the super-timeline:", "raw row"]],
    ["paste", ["Watson searched the pasted file:", "line"]],
    ["history", ["Watson searched the chat history:", "line"]],
  ]);

  function lookupHtml(l) {
    if (!l) return "";
    const shown = Number(l.shown);
    const matched = Number(l.matched);
    if (!Number.isFinite(shown) || !Number.isFinite(matched)) return "";
    const floor = l.matchedIsFloor ? "at least " : "";
    const count = matched > shown || l.matchedIsFloor ? `${fmt(shown)} of ${floor}${fmt(matched)}` : fmt(shown);
    const what = l.what ? ` (${esc(String(l.what))})` : "";
    const where = LOOKUP_WHERE.get(l.source);
    const noun = (n) => (shown === 1 && matched <= 1 ? n : n + "s");
    if (!where) {
      const head = l.source ? "Watson searched another source:" : "Watson looked up";
      const tail = l.source ? ` matching ${noun("event")}` : ` forensic-timeline ${noun("event")}`;
      return `<div class="watson-cov watson-lookup">${head} ${esc(count)}${tail}${what}</div>`;
    }
    const evicted = Number(l.capEvicted);
    const cap =
      l.source === "supertimeline" && Number.isFinite(evicted) && evicted > 0
        ? `<div class="watson-cov">⚠ The super-timeline removed ${esc(fmt(evicted))} old rows because of its size limit. ` +
          `This search can miss rows. Import the artifact again to search them.</div>`
        : "";
    return (
      `<div class="watson-cov watson-lookup">${where[0]} ${esc(count)} matching ${noun(where[1])}${what}</div>` +
      cap
    );
  }

  const lookupsHtml = (list) => (Array.isArray(list) ? list.map(lookupHtml).join("") : "");
  const lookupsOf = (t) =>
    Array.isArray(t.lookups) && t.lookups.length ? lookupsHtml(t.lookups) : lookupHtml(t.lookedUp);

  // R2: the question asked for a super-timeline search past the limit. The server sends the limit.
  function superCapHtml(t) {
    if (t.superCapHit !== true) return "";
    const n = Number(t.superCapLimit);
    const limit = Number.isFinite(n) && n > 0 ? `${fmt(n)} ` : "";
    return `<div class="watson-cov watson-lookup">Watson reached its limit of ${esc(limit)}super-timeline searches for this question.</div>`;
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

  // The server's Velociraptor launch note ("Nothing to approve: …", "Risky query: …") arrives as the
  // turn's own veloNote field (it is also appended to the text). It is drawn as its own warning block,
  // so Watson's promise ("approve it in the panel") never hides that there is no card. Only the server
  // sets veloNote: Watson's text can never forge the block (Task 9 review M-2), and an empty reply
  // still shows it (M-3).
  function textHtml(t) {
    const text = String(t.text || "");
    const note = typeof t.veloNote === "string" ? t.veloNote : "";
    if (!note) return `<div class="watson-text">${esc(text)}</div>`;
    const body = text.endsWith(note) ? text.slice(0, text.length - note.length).trim() : text;
    return (
      (body ? `<div class="watson-text">${esc(body)}</div>` : "") +
      `<div class="watson-why watson-warn watson-note" role="note">${esc(note)}</div>`
    );
  }

  // readOnly: an older turn paged back from the history file. It shows no proposal or add button.
  function turnHtml(t, proposals, readOnly, ctx) {
    const reacted = t.role === "system" && String(t.text).startsWith("Watson reacted to");
    const cls = "watson-turn watson-" + (t.error ? "warn" : t.role) + (reacted ? " watson-reacted" : "");
    const who = t.role === "analyst" ? esc(t.actor || "You") : t.role === "system" ? "System" : "Watson";
    const mine = readOnly ? [] : (t.proposalIds || []).map((id) => proposals.find((p) => p.id === id)).filter(Boolean);
    const props = mine.map(proposalHtml).join("") + watsonWroteHtml(mine);
    return (
      `<div class="${cls}"><div class="watson-who">${who}</div>` +
      (t.workingOn ? `<div class="watson-meta"><b>Watson works on:</b> ${esc(t.workingOn)}</div>` : "") +
      (autoList(t) || textHtml(t)) +
      answerHtml(t, readOnly, ctx) +
      coverageHtml(t.coverage) +
      lookupsOf(t) +
      superCapHtml(t) +
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
    if (!questions.length) return `<div class="watson-empty">There are no key questions.</div>`;
    return questions
      .map((q) => {
        const dis = q.synthesisDisagrees
          ? `<div class="q-contradicted">Synthesis does not agree: ${esc(q.synthesisDisagrees.status)}` +
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
      `<textarea class="watson-input" rows="2" placeholder="Ask Watson… (Enter sends. Ctrl+Enter starts a new line.)" aria-label="Message Watson"></textarea>` +
      `<div class="watson-paste-box"><textarea class="watson-paste-text" rows="5" placeholder="Paste evidence text here" aria-label="Paste evidence"></textarea>` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="pasteSend">Send paste</button></div>` +
      `<div class="watson-actions">` +
      `<button type="button" data-act="watsonAct" data-w-verb="send">Send</button> ` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="pasteToggle">Paste evidence</button> ` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="attachPick">Attach file</button> ` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="newThread" title="Start a new thread. Watson keeps its case memory. The earlier chat stays in the history.">↺ New thread</button>` +
      `<input type="file" class="watson-file" data-act="watsonAct" data-act-on="change" data-w-verb="file" accept=".txt,.log,.csv,.tsv,.json,.xml,text/*,application/json,application/xml" />` +
      `</div></div>`
    );
  }

  // Size-control icons (static markup, no case data): chevrons for expand/collapse, corners for full screen.
  const svg = (d) =>
    `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="${d}"/></svg>`;
  const ICON = {
    expand: svg("M11 17l-5-5 5-5M18 17l-5-5 5-5"),
    collapse: svg("M13 17l5-5-5-5M6 17l5-5-5-5"),
    full: svg("M8 3H3v5M16 3h5v5M8 21H3v-5M16 21h5v-5"),
    exitFull: svg("M3 8h5V3M21 8h-5V3M3 16h5v5M21 16h-5v5"),
    stop: svg("M6 6h12v12H6z"),
  };

  // One shell for all three states; the panel's classes decide what shows (see dashboard-watson.css).
  function panelHtml() {
    return (
      `<button type="button" class="watson-rail" data-act="watsonAct" data-w-verb="open" aria-expanded="false" aria-label="Open Watson" title="Open Watson">` +
      `<span class="watson-rail-expand" aria-hidden="true">${ICON.expand}</span>` +
      `<span class="watson-rail-icon">W</span><span class="watson-dot" data-w="dot"></span><span class="watson-count" data-w="count"></span><span data-w="railmode"></span></button>` +
      `<div class="watson-root watson-body"><div class="watson-head"><strong>Watson</strong><span class="watson-mode" data-w="mode"></span><span data-w="velo"></span>` +
      `<button type="button" class="watson-icon-btn watson-stop" data-w="stop" data-act="watsonAct" data-w-verb="stop" aria-label="Stop Watson" title="Stop Watson" hidden>${ICON.stop}</button>` +
      `<button type="button" class="watson-icon-btn watson-only-open" data-act="watsonAct" data-w-verb="fullScreen" aria-expanded="false" aria-label="Full screen" title="Full screen">${ICON.full}</button>` +
      `<button type="button" class="watson-icon-btn watson-only-full" data-act="watsonAct" data-w-verb="exitFullScreen" aria-expanded="true" aria-label="Exit full screen" title="Exit full screen">${ICON.exitFull}</button>` +
      `<button type="button" class="watson-icon-btn" data-act="watsonAct" data-w-verb="collapse" aria-expanded="true" aria-label="Collapse Watson" title="Collapse Watson">${ICON.collapse}</button></div>` +
      `<div class="watson-main"><div class="watson-board" data-w="board"></div>` +
      `<div class="watson-chat"><div class="watson-log" data-w="log"></div>` +
      composerHtml() +
      `<div class="watson-foot" data-w="foot"></div></div></div></div>`
    );
  }

  // The composer's Enter key: "send", "newline" (Ctrl, Cmd or Shift held) or null (not Enter, or an
  // IME composition is still open, so Enter belongs to the input method).
  function composerKey(e) {
    if (e.key !== "Enter" || e.isComposing || e.keyCode === 229) return null;
    return e.ctrlKey || e.metaKey || e.shiftKey ? "newline" : "send";
  }

  // A line break at the caret (replacing any selection), the caret left after it.
  function insertNewline(ta) {
    const start = Number.isInteger(ta.selectionStart) ? ta.selectionStart : ta.value.length;
    const end = Number.isInteger(ta.selectionEnd) ? ta.selectionEnd : start;
    if (typeof ta.setRangeText === "function") return ta.setRangeText("\n", start, end, "end");
    ta.value = ta.value.slice(0, start) + "\n" + ta.value.slice(end);
    ta.selectionStart = ta.selectionEnd = start + 1;
  }

  window.watsonComposerKey = composerKey;
  window.watsonInsertNewline = insertNewline;
  window.watsonTurnHtml = turnHtml;
  window.watsonBoardHtml = boardHtml;
  window.watsonEarlierButtonHtml = earlierButtonHtml;
  window.watsonCaseIsEmpty = caseIsEmpty;
  window.watsonPanelHtml = panelHtml;
})();
