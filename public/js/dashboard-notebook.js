// Analyst notebook — free-form case notes, some of which become tracked hypotheses — extracted
// from dashboard.html (issue #415, tier 3).
//
// Its one escape was a cross-module READ: dashboard-hypotheses.js's promoteToHypothesis() did
// `notebookEntries.find(e => e.id === id)`, reaching into this feature's array to build the
// notebook→hypothesis bridge from the far side. The bridge is fine; the reach is not. It asks
// notebookEntry(id) now, so the array stays private and the shape of an entry can change here
// without a second file silently depending on it.
(function () {
  "use strict";

  let notebookEntries = [];
  let nbEditingId = null;
  let notebookCaseId = null; // the case the list and the editor belong to

  function clearNotebook(caseId) {
    notebookCaseId = caseId;
    notebookEntries = [];
    if (document.getElementById("nbAddBtn")) nbCancelEdit();
    renderNotebook();
  }
  // #2915: a cancelled or failed case load drops the notes (and a half-finished edit) and unchecks the
  // AI box; the next open — the same case included — reads both again.
  function onNotebookReset(caseId) {
    if (caseId !== null) return;
    nbAiSeq++;
    nbAiCase = null;
    const box = document.getElementById("nbAiToggle");
    if (box) box.checked = false;
    clearNotebook(null);
    const list = document.getElementById("nbList");
    if (list) list.innerHTML = ""; // blank, not "No entries yet." — no case is loaded
  }
  const nbListenReset = () =>
    typeof DfirPanelDefer !== "undefined" && typeof DfirPanelDefer.onReset === "function" && DfirPanelDefer.onReset(onNotebookReset);
  function loadNotebook(caseId) {
    nbListenReset();
    // A different case (#2442): its half-finished edit and entry list must not carry over — "Save
    // edit" would PATCH the old case's entry id into the new case.
    if (caseId !== notebookCaseId) clearNotebook(caseId);
    fetch(`/cases/${caseId}/notebook`)
      .then((r) => r.json())
      .then((list) => {
        if (caseId !== notebookCaseId) return; // a late answer for the case left behind
        notebookEntries = Array.isArray(list) ? list : [];
        renderNotebook();
      })
      .catch(() => {});
  }

  // #2904: a load for another case unchecks the box at once (the server default) — the previous
  // case's choice must not show here; only the newest answer for the case on screen sets it.
  function nbOnScreen(caseId) {
    const el = document.getElementById("caseId");
    return !el || typeof el.value !== "string" || el.value.trim() === caseId;
  }
  let nbAiCase = null;
  let nbAiSeq = 0;
  function loadNbAiToggle(caseId) {
    if (!nbOnScreen(caseId)) return; // a late caller for a case the analyst has left
    nbListenReset();
    const el = document.getElementById("nbAiToggle");
    if (nbAiCase !== caseId) {
      nbAiCase = caseId;
      if (el) el.checked = false;
    }
    const seq = ++nbAiSeq;
    fetch(`/cases/${caseId}/ai-control`)
      .then((r) => r.json())
      .then((c) => {
        if (el && seq === nbAiSeq && nbOnScreen(caseId)) el.checked = !!c.includeNotebook;
      })
      .catch(() => {});
  }

  function renderNotebook() {
    const el = document.getElementById("nbList");
    if (!el) return;
    if (!notebookEntries.length) {
      el.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px'>No entries yet.</div>";
      return;
    }
    el.innerHTML = notebookEntries
      .map((e) => {
        const who = e.author
          ? `<span data-safe-style="font-size:10px;color:var(--text-primary);font-weight:600">${esc(e.author)}</span>`
          : "";
        const ts = e.timestamp
          ? `<span data-safe-style="margin-left:auto;font-size:10px;color:var(--text-faint)">${esc(e.timestamp.slice(0, 16).replace("T", " "))} UTC</span>`
          : "";
        const promote = `<button class="nb-action-btn" data-act="promoteToHypothesis" data-id="${escAttr(e.id)}" title="Track this as a status-bearing hypothesis (Hypotheses panel)">→ Hypothesis</button>`;
        return (
          `<div class="nb-entry ${escAttr(e.type)}" data-id="${escAttr(e.id)}">` +
          `<div class="nb-entry-header"><span class="nb-type-badge ${escAttr(e.type)}">${esc(e.type)}</span>${who}${ts}</div>` +
          `<div class="nb-entry-text">${esc(e.text)}</div>` +
          `<div class="nb-entry-actions">` +
          promote +
          `<button class="nb-action-btn" data-act="nbStartEdit" data-id="${escAttr(e.id)}">Edit</button>` +
          `<button class="nb-action-btn del" data-act="nbDelete" data-id="${escAttr(e.id)}">Delete</button>` +
          `</div></div>`
        );
      })
      .join("");
  }

  function nbStartEdit(id) {
    const entry = notebookEntries.find((e) => e.id === id);
    if (!entry) return;
    nbEditingId = id;
    document.getElementById("nbText").value = entry.text;
    document.getElementById("nbType").value = entry.type;
    document.getElementById("nbAddBtn").textContent = "Save edit";
    document.getElementById("nbMsg").textContent = "";
    document.getElementById("nbText").focus();
  }

  function nbCancelEdit() {
    nbEditingId = null;
    document.getElementById("nbText").value = "";
    document.getElementById("nbType").value = "note";
    document.getElementById("nbAddBtn").textContent = "Add entry";
    document.getElementById("nbMsg").textContent = "";
  }

  function nbDelete(id) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    fetch(`/cases/${caseId}/notebook/${id}`, { method: "DELETE" })
      .then(async (r) => {
        // A refused delete (a closed case answers 423, #2437) says why instead of failing silently.
        if (!r.ok) {
          const msg = document.getElementById("nbMsg");
          if (msg) msg.textContent = "failed: " + ((await r.json().catch(() => ({}))).error || "HTTP " + r.status);
        }
        loadNotebook(caseId);
      })
      .catch(() => {});
  }

  // Hypotheses (issue #140) live in public/js/dashboard-hypotheses.js.

  // What the hypotheses module needs to build the bridge: one entry, by id.
  function notebookEntry(id) {
    return notebookEntries.find((e) => e.id === id);
  }

  // The add / delete / edit controls, all binding to markup.
  function initNotebook() {
    document.getElementById("nbAddBtn").onclick = function () {
      const caseId = document.getElementById("caseId").value.trim();
      const text = document.getElementById("nbText").value.trim();
      const type = document.getElementById("nbType").value;
      const msg = document.getElementById("nbMsg");
      if (!caseId || !text) {
        msg.textContent = "text required";
        return;
      }
      msg.textContent = nbEditingId ? "saving…" : "adding…";
      if (nbEditingId) {
        fetch(`/cases/${caseId}/notebook/${nbEditingId}`, {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ text, type }),
        })
          .then(async (r) => {
            // The server's own sentence: a closed case answers 423 "reopen it before changing it" (#2437).
            if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || "HTTP " + r.status);
            return r.json();
          })
          .then(() => {
            nbCancelEdit();
            loadNotebook(caseId);
          })
          .catch((e) => {
            msg.textContent = "failed: " + e.message;
          });
      } else {
        fetch(`/cases/${caseId}/notebook`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ text, type, author: investigatorName() }),
        })
          .then(async (r) => {
            // The server's own sentence: a closed case answers 423 "reopen it before changing it" (#2437).
            if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || "HTTP " + r.status);
            return r.json();
          })
          .then(() => {
            document.getElementById("nbText").value = "";
            msg.textContent = "";
            loadNotebook(caseId);
          })
          .catch((e) => {
            msg.textContent = "failed: " + e.message;
          });
      }
    };
    document
      .getElementById("nbAiToggle")
      .addEventListener("change", function () {
        const caseId = document.getElementById("caseId").value.trim();
        if (!caseId) {
          this.checked = !this.checked;
          return;
        }
        fetch(`/cases/${caseId}/ai-control`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            enabled: aiEnabled,
            includeNotebook: this.checked,
          }),
        }).catch(() => {
          this.checked = !this.checked;
        });
      });
  }

  window.initNotebook = initNotebook;
  window.loadNotebook = loadNotebook;
  window.loadNbAiToggle = loadNbAiToggle;
  window.nbDelete = nbDelete;
  window.nbStartEdit = nbStartEdit;
  window.notebookEntry = notebookEntry;
})();
