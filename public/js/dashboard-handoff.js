// Handoff Brief (#1406).
//
// What the case holds, what is open, what to check next — derived on the server from the case as
// it stands (GET /cases/:id/handoff) — plus the outgoing analyst's own note, which is a notebook
// entry of type "handoff" (POST /cases/:id/notebook, the existing route), so a re-synthesis never
// wipes it and the Notebook panel shows it with its own badge. "Copy as Markdown" hands the same
// brief to a shift log. A count is a count; the words are the analyst's.
//
// An IIFE for the same reason as js/dashboard-campaign-scope.js: this feature owns state.
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  let brief = null;
  let markdown = "";
  let currentCaseId = "";
  let loadGen = 0;
  let status = "loading"; // "loading" | "loaded" | "error": a failed request is never an empty case

  const when = (iso) => (iso ? String(iso).slice(0, 16).replace("T", " ") + " UTC" : "unknown");
  const num = (v) => Number(v || 0).toLocaleString("en-US");
  const more = (n, what) => (n > 0 ? `<li data-safe-style="color:var(--text-muted)">… and ${num(n)} more ${esc(what)}</li>` : "");
  const list = (items, render, notShown, what, empty) =>
    items.length || notShown
      ? `<ul data-safe-style="margin:2px 0 6px 18px;padding:0">${items.map(render).join("")}${more(notShown, what)}</ul>`
      : `<div data-safe-style="color:var(--text-muted);font-size:12px;margin:2px 0 6px 18px">${esc(empty)}</div>`;

  function renderBrief() {
    const el = document.getElementById("handoffPanel");
    if (!el) return;
    if (status === "loading") {
      el.innerHTML = `<div data-safe-style='color:var(--text-muted);font-size:12px'>Loading…</div>`;
      return;
    }
    if (status === "error") {
      el.innerHTML = `<div data-safe-style='color:var(--danger, #b00);font-size:12px'>The handoff brief could not be loaded (${esc((brief && brief.error) || "request failed")}). Nothing here says the case is empty.</div>`;
      return;
    }
    const b = brief;
    const f = b.findings;
    const sev = Object.keys(f.bySeverity).map((k) => `${esc(k)} ${num(f.bySeverity[k])}`).join(", ");
    const notes = b.handoffNotes.length
      ? b.handoffNotes
          .map(
            (n, i) =>
              `<div class="nb-entry handoff" data-safe-style="${i ? "opacity:.8" : ""}"><div class="nb-entry-header"><span class="nb-type-badge handoff">handoff</span><span data-safe-style="font-weight:600;color:var(--text-primary)">${esc(n.author)}</span><span data-safe-style="margin-left:auto;color:var(--text-faint)">${esc(when(n.timestamp))}</span></div><div class="nb-entry-text">${esc(n.text)}</div></div>`,
          )
          .join("") + (b.handoffNotesNotShown ? `<div data-safe-style="font-size:11px;color:var(--text-muted)">… and ${num(b.handoffNotesNotShown)} earlier note(s) in the notebook.</div>` : "")
      : `<div data-safe-style="color:var(--text-muted);font-size:12px">No handoff note recorded yet — write one below.</div>`;
    el.innerHTML = `
      <div data-safe-style="font-size:11px;color:var(--text-muted);margin-bottom:6px">Derived from the case as of ${esc(when(b.stateUpdatedAt))}${b.lastImport ? `; last import ${esc(when(b.lastImport.at))} (${esc(b.lastImport.kind)}${b.lastImport.source ? `, ${esc(b.lastImport.source)}` : ""})` : "; no import recorded"}; a count is not a conclusion.</div>
      <h3 data-safe-style="font-size:13px;margin:8px 0 4px">From the outgoing analyst</h3>
      ${notes}
      <h3 data-safe-style="font-size:13px;margin:10px 0 4px">What the case holds</h3>
      <ul data-safe-style="margin:2px 0 6px 18px;padding:0;font-size:12px">
        <li>Findings: ${num(f.byStatus.open + f.byStatus.confirmed + f.byStatus.dismissed)} (${num(f.byStatus.open)} open, ${num(f.byStatus.confirmed)} confirmed, ${num(f.byStatus.dismissed)} dismissed) — ${sev}</li>
        <li>IOCs: ${num(b.iocs.total)}${b.iocs.unenriched ? ` (${num(b.iocs.unenriched)} not yet checked by any provider)` : ""}</li>
      </ul>
      <h3 data-safe-style="font-size:13px;margin:10px 0 4px">Open</h3>
      <div data-safe-style="font-size:12px"><b>Findings still open (${num(f.openTotal)}; ${num(f.inProgress)} in progress, ${num(f.unassigned)} unassigned)</b>
      ${list(f.open, (x) => `<li><span class="sev-${esc(String(x.severity).toLowerCase())}">[${esc(x.severity)}]</span> ${esc(x.title)} <code>${esc(x.id)}</code>${x.assignee ? ` — ${esc(x.assignee)}` : ""}${x.workflowStatus ? ` <span data-safe-style="color:var(--text-muted)">(${esc(x.workflowStatus)})</span>` : ""}</li>`, f.openNotShown, "findings", "none")}
      <b>Key questions not answered</b>
      ${list(b.questions, (q) => `<li>(${esc(q.status)}) ${esc(q.question)}${q.pointer ? ` <span data-safe-style="color:var(--text-muted)">— ${esc(q.pointer)}</span>` : ""}</li>`, b.questionsNotShown, "questions", "none")}
      <b>Hypotheses still open</b>
      ${list(b.hypotheses, (h) => `<li>${esc(h.title)}</li>`, b.hypothesesNotShown, "hypotheses", "none")}
      <b>Threads open</b>
      ${list(b.threads, (t) => `<li>${esc(t.description)} <span data-safe-style="color:var(--text-muted)">(since ${esc(when(t.openedAt))})</span></li>`, b.threadsNotShown, "threads", "none")}</div>
      <h3 data-safe-style="font-size:13px;margin:10px 0 4px">Check next</h3>
      <div data-safe-style="font-size:12px">${list(b.nextSteps, (n) => `<li>[${esc(n.priority)}] ${esc(n.action)}${n.pointer ? ` <span data-safe-style="color:var(--text-muted)">— ${esc(n.pointer)}</span>` : ""}</li>`, b.nextStepsNotShown, "steps", "no critical or high next step recorded")}</div>`;
  }

  function loadHandoff(caseId) {
    currentCaseId = caseId;
    brief = null;
    markdown = "";
    status = "loading";
    renderBrief();
    const gen = ++loadGen;
    // A late answer for a case the user has left, or an older load, never overwrites the panel.
    fetch(`/cases/${encodeURIComponent(caseId)}/handoff`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        if (!d || !d.brief || !d.brief.findings) throw new Error("malformed brief");
        brief = d.brief;
        markdown = typeof d.markdown === "string" ? d.markdown : "";
        status = "loaded";
        renderBrief();
      })
      .catch((err) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        brief = { error: String((err && err.message) || err) };
        status = "error";
        renderBrief();
      });
  }

  function initHandoff() {
    const msg = document.getElementById("handoffMsg");
    const say = (t, bad) => {
      if (!msg) return;
      msg.textContent = t;
      msg.style.color = bad ? "var(--danger, #b00)" : "var(--text-muted)";
    };
    const save = document.getElementById("handoffSaveBtn");
    if (save)
      save.onclick = () => {
        const ta = document.getElementById("handoffText");
        const text = (ta && ta.value.trim()) || "";
        if (!text || !currentCaseId) return say("Write the note first.", true);
        save.disabled = true;
        fetch(`/cases/${encodeURIComponent(currentCaseId)}/notebook`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text, type: "handoff", author: typeof investigatorName === "function" ? investigatorName() : "" }),
        })
          .then((r) => {
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            ta.value = "";
            say("Handoff note saved to the notebook.");
            loadHandoff(currentCaseId);
            if (typeof loadNotebook === "function") loadNotebook(currentCaseId);
          })
          .catch((err) => say(`Could not save: ${String((err && err.message) || err)}`, true))
          .finally(() => {
            save.disabled = false;
          });
      };
    const copy = document.getElementById("handoffCopyBtn");
    if (copy)
      copy.onclick = () => {
        if (!markdown) return say("Nothing to copy yet.", true);
        const done = () => say("Brief copied as Markdown.");
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(markdown).then(done, () => fallbackCopy(done));
        else fallbackCopy(done);
      };
    function fallbackCopy(done) {
      const ta = document.createElement("textarea");
      ta.value = markdown;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        done();
      } catch (e) {
        say("Copy failed — select the text in the notebook instead.", true);
      }
      ta.remove();
    }
  }

  window.loadHandoff = loadHandoff;
  window.initHandoff = initHandoff;
})();
