// Watson's markup: pure HTML builders for the chat turns, the proposals, the Key Questions board and
// the two shells (side panel, full section). No state lives here; dashboard-watson.js owns it and
// calls the five published builders by name. Split out so each file stays under 400 lines.
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
    return (
      `<div class="watson-req"><div class="watson-lbl">Import ${esc(r.what)}</div>` +
      `<div class="watson-why">${esc(r.why)}</div></div>`
    );
  }

  const btn = (pid, verb, label) =>
    `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="${verb}" data-pid="${escAttr(pid)}">${label}</button> `;

  function proposalHtml(p) {
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

  function turnHtml(t, proposals) {
    const cls = "watson-turn watson-" + (t.error ? "warn" : t.role);
    const who = t.role === "analyst" ? esc(t.actor || "You") : t.role === "system" ? "System" : "Watson";
    const props = (t.proposalIds || [])
      .map((id) => proposals.find((p) => p.id === id))
      .filter(Boolean)
      .map(proposalHtml)
      .join("");
    return (
      `<div class="${cls}"><div class="watson-who">${who}</div>` +
      (t.workingOn ? `<div class="watson-meta"><b>Working on:</b> ${esc(t.workingOn)}</div>` : "") +
      `<div class="watson-text">${esc(t.text)}</div>` +
      (t.learned ? `<div class="watson-meta"><b>Learned:</b> ${esc(t.learned)}</div>` : "") +
      requestHtml(t.request) +
      props +
      `</div>`
    );
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
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="attachPick">Attach file</button>` +
      `<input type="file" class="watson-file" data-act="watsonAct" data-act-on="change" data-w-verb="file" accept=".txt,.log,.csv,.tsv,.json,.xml,text/*,application/json,application/xml" />` +
      `</div></div>`
    );
  }

  function panelHtml() {
    return (
      `<button type="button" class="watson-rail" data-act="watsonAct" data-w-verb="collapse" aria-expanded="false" aria-label="Open Watson">` +
      `<span class="watson-rail-icon">W</span><span class="watson-dot" data-w="dot"></span><span class="watson-count" data-w="count"></span></button>` +
      `<div class="watson-root watson-full"><div class="watson-head"><strong>Watson</strong>` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="expand">Expand</button>` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="collapse" aria-expanded="true" aria-label="Collapse Watson">Collapse</button></div>` +
      `<div class="watson-log" data-w="log"></div>` +
      composerHtml() +
      `<div class="watson-foot" data-w="foot"></div></div>`
    );
  }

  function sectionHtml() {
    return (
      `<div class="watson-root watson-wide"><div class="watson-board" data-w="board"></div>` +
      `<div class="watson-chat"><div class="watson-log" data-w="log"></div>` +
      composerHtml() +
      `<div class="watson-foot" data-w="foot"></div></div></div>`
    );
  }

  window.watsonTurnHtml = turnHtml;
  window.watsonBoardHtml = boardHtml;
  window.watsonPanelHtml = panelHtml;
  window.watsonSectionHtml = sectionHtml;
})();
