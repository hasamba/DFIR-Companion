// The case's main evidence source (#2559): the line + override dropdown at the top of the Suggested
// Hunts panel, and the copy-ready hunt cards written in that source's query language.
//
// The server decides everything (GET/PUT /cases/:id/main-source; the hunt routes pick the language).
// This file only shows it:
//   - the line: "Main evidence source: CrowdStrike Falcon (14 of 15 evidence files) — hunts are
//     written in CrowdStrike Falcon CQL", or "Mixed evidence", with an Automatic / per-source / Mixed
//     dropdown. Changing it clears the shown hunts so the next press uses the new language;
//   - the language cards (fleet hunts and per-task playbook hunts): the AI-written query, Copy and
//     Regenerate. There is NO deploy button — only Velociraptor VQL is deployable, and VQL hunts keep
//     their own cards in dashboard-hunts-jumps.js / dashboard-playbook.js, unchanged.
// Everything the server or the model sent is rendered through esc()/escAttr().
(function () {
  "use strict";

  const LANGUAGE_LABELS = {
    cql: "CrowdStrike Falcon CQL",
    "kql-device": "Defender / Sentinel KQL",
    "kql-cloud": "Sentinel KQL (sign-in and audit logs)",
    esql: "Elastic ES|QL",
    spl: "Splunk SPL",
  };

  let msState = null; // the last GET /cases/:id/main-source answer
  let fleetLangHunts = []; // fleet hunts in the main-source language, as shown
  let fleetNotes = []; // the fallback / no-language notes shown with them
  let pbLangHunts = []; // per-task playbook hunts in a non-VQL language

  const caseIdOf = () => {
    const el = document.getElementById("caseId");
    return el ? el.value.trim() : "";
  };

  function filesOf(ms, family) {
    const c = (ms.counts || []).find((x) => x.family === family);
    return c ? c.files : 0;
  }

  function labelOf(ms, family) {
    const f = (ms.families || []).find((x) => x.family === family);
    return f ? f.label : family;
  }

  function lineText(ms) {
    const mine = ms.override ? " (set by you)" : "";
    if (!ms.effective) return "No evidence in the forensic timeline yet — hunts default to Velociraptor VQL.";
    if (ms.effective === "mixed")
      return `Mixed evidence${mine} — no source has 70% of the evidence files, so each hunt uses the language of its own evidence.`;
    const lang = ms.language && ms.language.language ? ` — hunts are written in ${ms.language.label}` : "";
    return `Main evidence source: ${labelOf(ms, ms.effective)}${mine} (${filesOf(ms, ms.effective)} of ${ms.totalFiles} evidence files that reached the forensic timeline)${lang}.`;
  }

  function lineHtml(ms) {
    const sel = ms.override || "";
    const opt = (v, label) => `<option value="${escAttr(v)}"${v === sel ? " selected" : ""}>${esc(label)}</option>`;
    const options = [opt("", "Automatic"), ...(ms.families || []).map((f) => opt(f.family, f.label)), opt("mixed", "Mixed (per finding)")];
    const note = ms.language && ms.language.note ? `<div class="ms-note" data-safe-style="color:var(--text-muted)">${esc(ms.language.note)}</div>` : "";
    return (
      `<div class="ms-line" data-safe-style="font-size:12px;margin:4px 0 8px">` +
      `<span class="ms-text">${esc(lineText(ms))}</span> ` +
      `<label data-safe-style="margin-left:6px">Change main source <select id="mainSourceSelect" aria-label="Change the case's main evidence source">${options.join("")}</select></label>` +
      note +
      `</div>`
    );
  }

  // #2594: the playbook button names the main source's language. VQL text is today's, unchanged.
  const VQL_BUTTON = {
    text: "✨ Suggest Velociraptor hunts",
    title:
      "Ask the AI to suggest a Velociraptor hunt for each endpoint-related task — a fleet hunt, or a single-endpoint collection when the task is tied to one host (review the VQL before deploying)",
  };
  const BUTTON_WORDS = { cql: "Falcon", "kql-device": "KQL", "kql-cloud": "KQL", esql: "ES|QL", spl: "SPL" };

  function playbookHuntButton(ms) {
    const lang = ms && ms.language && ms.language.language;
    if (lang && BUTTON_WORDS[lang])
      return {
        text: `✨ Suggest ${BUTTON_WORDS[lang]} queries`,
        title: `Ask the AI to write ${ms.language.label || LANGUAGE_LABELS[lang]} queries for the open playbook tasks they apply to — copy-ready; review each query before you run it`,
      };
    if (ms && ms.effective === "mixed")
      return {
        text: "✨ Suggest hunts",
        title:
          "Mixed evidence: each task uses the language of its finding's evidence; a task with no finding evidence falls back to Velociraptor VQL. Review each query before you run it.",
      };
    if (ms && ms.effective === "cloud-other")
      return {
        text: "✨ Suggest hunts",
        title:
          "Other cloud logs have no hunt query language yet, so this button writes no queries for them — use the Query Translator instead.",
      };
    return VQL_BUTTON;
  }

  function renderPlaybookHuntButton() {
    const btn = document.getElementById("pbHuntBtn");
    if (!btn) return;
    const b = playbookHuntButton(msState);
    btn.textContent = b.text;
    btn.title = b.title;
  }

  function renderMainSourceLine() {
    renderPlaybookHuntButton();
    const el = document.getElementById("mainSourceLine");
    if (!el) return;
    if (!msState) {
      el.innerHTML = "";
      return;
    }
    el.innerHTML = lineHtml(msState);
    const sel = document.getElementById("mainSourceSelect");
    if (sel) sel.onchange = () => setMainSource(sel.value);
  }

  function loadMainSource() {
    const caseId = caseIdOf();
    if (!caseId) return Promise.resolve();
    return fetch(`/cases/${encodeURIComponent(caseId)}/main-source`)
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        msState = j;
        renderMainSourceLine();
      })
      .catch(() => {
        msState = null;
        renderMainSourceLine();
      });
  }

  function setMainSource(value) {
    const caseId = caseIdOf();
    if (!caseId) return;
    fetch(`/cases/${encodeURIComponent(caseId)}/main-source`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ override: value || null }),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok) throw new Error(j.error || "could not change the main source");
        msState = j;
        renderMainSourceLine();
        // The shown hunts were written for the old language: clear them so the next press uses the new one.
        fleetLangHunts = [];
        fleetNotes = [];
        if (typeof resetVeloHuntSuggest === "function") resetVeloHuntSuggest();
        if (typeof loadPlaybook === "function") loadPlaybook(caseId);
      })
      .catch((e) => {
        const el = document.getElementById("mainSourceLine");
        if (el) el.insertAdjacentHTML("beforeend", `<div data-safe-style="color:var(--sev-high)">${esc(e.message)}</div>`);
      });
  }

  function cardHtml(h, idx, scope) {
    const sev = h.severity || "Medium";
    const sevColor = (typeof VHS_SEV_COLOR !== "undefined" && VHS_SEV_COLOR[sev]) || "#9aa4b2";
    const techs = (h.mitreTechniques || []).map((t) => `<span class="vhs-tech">${esc(t)}</span>`).join("");
    const cites = typeof citeFindings === "function" ? citeFindings(h.relatedFindingIds || []) : "";
    const label = LANGUAGE_LABELS[h.language] || h.language;
    return (
      `<div class="vhs-card msh-card" data-scope="${escAttr(scope)}" data-idx="${idx}">` +
      `<div class="vhs-head"><span class="vhs-title">${esc(h.title)}</span>` +
      `<span class="vhs-sev" data-safe-style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}55">${esc(sev)}</span>` +
      `<span class="vhs-tech" title="Copy-ready: run it in that tool yourself — it is never deployed">${esc(label)} · copy-ready</span></div>` +
      (h.rationale ? `<div class="vhs-rationale">${esc(h.rationale)}</div>` : "") +
      (cites ? `<div class="vhs-rationale" data-safe-style="color:var(--text-muted)">Cites: ${cites}</div>` : "") +
      (techs ? `<div class="vhs-techs">${techs}</div>` : "") +
      `<textarea class="vhs-vql msh-query" spellcheck="false" aria-label="${escAttr(label)} query">${esc(h.query)}</textarea>` +
      `<div class="vhs-actions"><button type="button" class="msh-copy">Copy query</button>` +
      `<button type="button" class="msh-regen" title="Ask the AI for a different ${escAttr(label)} hunt">↻ Regenerate</button></div>` +
      `</div>`
    );
  }

  function notesHtml(notes) {
    return (notes || []).map((n) => `<div class="vhs-caveat">${esc(n)}</div>`).join("");
  }

  function wireCopy(root) {
    root.querySelectorAll(".msh-copy").forEach((b) => {
      b.onclick = (e) => {
        e.stopPropagation();
        const q = b.closest(".msh-card").querySelector(".msh-query");
        navigator.clipboard
          .writeText(q ? q.value : "")
          .then(() => {
            b.textContent = "Copied ✓";
            setTimeout(() => (b.textContent = "Copy query"), 1500);
          })
          .catch(() => (b.textContent = "copy failed"));
      };
    });
  }

  function postJson(url, body) {
    return fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) throw new Error(j.error || "regenerate failed");
        return j;
      });
  }

  // Fleet hunts: appended under the VQL cards (or alone) in #veloHuntSuggest. Called with only `el`, it
  // re-appends the last set — a VQL card's regenerate re-renders #veloHuntSuggest and would drop it.
  function renderLanguageHunts(el, hunts, notes) {
    if (!el) return;
    if (hunts !== undefined) {
      fleetLangHunts = Array.isArray(hunts) ? hunts : [];
      fleetNotes = Array.isArray(notes) ? notes : [];
    }
    let block = el.querySelector(".msh-block");
    if (!fleetLangHunts.length && !fleetNotes.length) {
      if (block) block.remove();
      return;
    }
    if (!block) {
      block = document.createElement("div");
      block.className = "msh-block";
      el.appendChild(block);
    }
    const caveat = fleetLangHunts.length
      ? `<div class="vhs-caveat">⚠ AI-written queries in the case's main evidence source language — review each one, then copy it into that tool. They are never deployed from here.</div>`
      : "";
    block.innerHTML = notesHtml(fleetNotes) + caveat + `<div class="vhs-list">${fleetLangHunts.map((h, i) => cardHtml(h, i, "fleet")).join("")}</div>`;
    wireCopy(block);
    block.querySelectorAll(".msh-regen").forEach((b) => {
      b.onclick = () => regenFleet(Number(b.closest(".msh-card").dataset.idx), b, el);
    });
  }

  function regenFleet(idx, btn, el) {
    const cur = fleetLangHunts[idx];
    const caseId = caseIdOf();
    if (!cur || !caseId) return;
    const q = btn.closest(".msh-card").querySelector(".msh-query");
    btn.disabled = true;
    btn.textContent = "⏳ thinking…";
    postJson(`/cases/${encodeURIComponent(caseId)}/velociraptor/suggest-hunts`, {
      language: cur.language,
      excludeQuery: q && q.value.trim() ? q.value : cur.query,
    })
      .then((j) => {
        const next = (j.languageHunts || [])[0];
        if (next) fleetLangHunts = fleetLangHunts.map((h, i) => (i === idx ? next : h));
        renderLanguageHunts(el, fleetLangHunts, fleetNotes);
      })
      .catch((e) => {
        btn.disabled = false;
        btn.textContent = "regen failed: " + e.message;
      });
  }

  // Playbook: the language cards sit under their task, beside any VQL card.
  function setPlaybookLanguageHunts(hunts) {
    pbLangHunts = Array.isArray(hunts) ? hunts : [];
  }

  function playbookLanguageHuntsHtml(taskId) {
    return pbLangHunts
      .map((h, i) => (h.taskId === taskId ? cardHtml({ ...h, relatedFindingIds: [] }, i, "pb") : ""))
      .join("");
  }

  function wirePlaybookLanguageHunts(container, rerender) {
    wireCopy(container);
    container.querySelectorAll('.msh-card[data-scope="pb"] .msh-regen').forEach((b) => {
      b.onclick = (e) => {
        e.stopPropagation();
        const idx = Number(b.closest(".msh-card").dataset.idx);
        const cur = pbLangHunts[idx];
        const caseId = caseIdOf();
        if (!cur || !caseId) return;
        const q = b.closest(".msh-card").querySelector(".msh-query");
        b.disabled = true;
        b.textContent = "⏳ thinking…";
        postJson(`/cases/${encodeURIComponent(caseId)}/playbook/suggest-hunts`, {
          taskId: cur.taskId,
          language: cur.language,
          excludeQuery: q && q.value.trim() ? q.value : cur.query,
        })
          .then((j) => {
            if (Array.isArray(j.languageSuggestions)) pbLangHunts = j.languageSuggestions;
            if (typeof rerender === "function") rerender();
          })
          .catch((err) => {
            b.disabled = false;
            b.textContent = "regen failed: " + err.message;
          });
      };
    });
  }

  window.loadMainSource = loadMainSource;
  window.playbookHuntButton = playbookHuntButton;
  window.renderLanguageHunts = renderLanguageHunts;
  window.setPlaybookLanguageHunts = setPlaybookLanguageHunts;
  window.playbookLanguageHuntsHtml = playbookLanguageHuntsHtml;
  window.wirePlaybookLanguageHunts = wirePlaybookLanguageHunts;
})();
