// Defensive countermeasures, D3FEND (#178) (#415 tier 3).
//
// Offline and deterministic — no AI. Derived server-side and re-derived on each state change.
//
// AN IIFE, unlike js/dashboard-tagger.js and js/dashboard-kev.js. Those hold no state, so their
// top-level declarations were harmless. This feature owns state, and a top-level `let` in a
// classic script joins the global LEXICAL environment — reachable by name from every other script
// on the page, which is the hazard js/dashboard-state.js sets out at length. Wrapping it is what
// makes "feature-local" true rather than merely intended.
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  // ── Defensive Countermeasures (D3FEND, #178) ─────────────────────────────────────────────
  // For each ATT&CK technique the case identified, the MITRE D3FEND countermeasures that harden
  // against / detect / isolate it. Offline + deterministic (no AI). Derived server-side
  // (GET /cases/:id/d3fend-countermeasures); re-derived (debounced) on each state change.
  let d3fendData = null;
  let d3fendTimer = null;
  function loadD3fend(caseId) {
    fetch(`/cases/${caseId}/d3fend-countermeasures`).then(r => r.json()).then(d => {
      d3fendData = (d && typeof d === "object") ? d : null;
      renderD3fend();
    }).catch(() => {});
  }
  function scheduleD3fendReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(d3fendTimer);
    d3fendTimer = setTimeout(() => loadD3fend(caseId), 800);
  }
  function renderD3fend() {
    const el = document.getElementById("d3fendPanel");
    if (!el) return;
    const d = d3fendData;
    // This block is the SECONDARY layer (defensive techniques / sensors); the actionable ATT&CK
    // mitigations render above it in #mitigationsPanel.
    const secHdr = `<div class="d3f-section-h">🛡 Defensive techniques &amp; sensors (D3FEND) — detection &amp; hardening categories</div>`;
    const note = secHdr + `<div class="d3f-note">${esc((d && d.note) || "Suggested D3FEND countermeasures — review for fit, not a complete or guaranteed list.")}</div>`;
    if (!d || !d.mappedTechniqueCount) {
      el.innerHTML = note + `<div class="d3f-empty">D3FEND mapping not available — run <code>npm run data:update-d3fend</code>.</div>`;
      return;
    }
    if (!d.caseTechniqueCount) {
      el.innerHTML = note + `<div class="d3f-empty">No techniques identified yet — countermeasures need at least one ATT&CK technique.</div>`;
      return;
    }
    if (!d.coveredTechniqueCount) {
      el.innerHTML = note + `<div class="d3f-empty">None of the case's ${esc(d.caseTechniqueCount)} identified technique(s) have a D3FEND countermeasure mapping.</div>`;
      return;
    }
    // Plain-language action label + meaning + concrete "what to do" + lifecycle tier per D3FEND
    // tactic (mirrors D3FEND_ACTION_INFO on the server) so the analyst doesn't decode raw jargon
    // and can see WHERE the actual hardening is.
    const ACTION = {
      Harden:  { emoji: "🔒", label: "Prevent", blurb: "stop it happening again",        guidance: "Apply the config / credential / patch change that removes the weakness the attacker used (e.g. enable MFA, disable the abused feature, restrict permissions)." },
      Detect:  { emoji: "🔍", label: "Detect",  blurb: "spot it if it recurs",            guidance: "Make sure logging or an EDR/SIEM rule will catch this behaviour next time, then verify the alert fires." },
      Isolate: { emoji: "⛔", label: "Contain", blurb: "limit the blast radius",          guidance: "Segment the network, sandbox the app, or tighten privileges so this technique can't spread." },
      Evict:   { emoji: "🧹", label: "Evict",   blurb: "remove the attacker's foothold",  guidance: "Do this during THIS incident: kill the malicious processes, delete persistence, reset compromised credentials." },
      Restore: { emoji: "♻️", label: "Restore", blurb: "recover affected systems",        guidance: "Do this during THIS incident: restore affected data, configs, and accounts from a known-good state." },
      Model:   { emoji: "🗺️", label: "Model",   blurb: "know your attack surface",        guidance: "Prerequisite hygiene, not a fix: keep asset/data/account inventories so you can find and scope what's affected." },
      Deceive: { emoji: "🎭", label: "Deceive", blurb: "lure & mislead the attacker",     guidance: "Optional / advanced: deploy decoys or honeytokens to detect and study intruders — only if your program is mature." },
    };
    const totalCms = (d.byTactic || []).reduce((n, g) => n + ((g.countermeasures || []).length), 0);
    const meta = `<div class="d3f-meta">${esc(totalCms)} countermeasure(s) covering ${esc(d.coveredTechniqueCount)} of ${esc(d.caseTechniqueCount)} identified ATT&CK technique(s) · MITRE D3FEND v${esc(d.d3fendVersion)} · <em>hover a countermeasure for its definition</em></div>`;
    // One section per defensive action: a header + a plain-English "what to do", then the
    // countermeasures (definition on hover) with the case technique(s) each addresses.
    const COVERS_CAP = 6; // keep each row compact even when a countermeasure covers many techniques
    const d3fGroup = g => {
      const a = ACTION[g.tactic] || { emoji: "🛡", label: g.tactic, blurb: "", guidance: "" };
      const rows = (g.countermeasures || []).map(c => {
        const techs = c.techniques || [];
        const covers = techs.slice(0, COVERS_CAP).map(t => {
          const u = attackUrl(t);
          return u ? `<a href="${escAttr(u)}" target="_blank" rel="noopener" class="d3f-cover">${esc(t)}</a>` : `<span class="d3f-cover">${esc(t)}</span>`;
        }).join("");
        const moreN = techs.length - COVERS_CAP;
        const more = moreN > 0 ? `<span class="d3f-cover-more" title="${escAttr(techs.join(", "))}">+${esc(moreN)} more</span>` : "";
        const coversBlock = techs.length ? `<span class="d3f-covers">covers ${covers}${more}</span>` : "";
        // Definition (+ D3FEND category) on hover over the name — the practical "what is this".
        const tip = [c.definition || "", c.category ? ("D3FEND category: " + c.category) : ""].filter(Boolean).join("\n\n");
        return `<div class="d3f-row"><a href="${escAttr(c.url)}" target="_blank" rel="noopener" class="d3f-cm" title="${escAttr(tip)}">${esc(c.name)}</a>${coversBlock}</div>`;
      }).join("");
      const guide = a.guidance ? `<div class="d3f-act-guide">→ ${esc(a.guidance)}</div>` : "";
      return `<div class="d3f-act">` +
        `<div class="d3f-act-h"><span class="d3f-act-emoji">${a.emoji}</span><span class="d3f-act-label">${esc(a.label)}</span><span class="d3f-act-blurb">— ${esc(a.blurb)}</span><span class="d3f-act-count" title="countermeasures">${esc((g.countermeasures || []).length)}</span></div>` +
        guide +
        `<div class="d3f-act-list">${rows}</div>` +
      `</div>`;
    };
    // Two bands: the proactive hardening to do now, then incident-response + prerequisite context.
    const BAND1 = ["Harden", "Detect", "Isolate"];
    const BAND2 = ["Evict", "Restore", "Model", "Deceive"];
    const ordIdx = (arr, t) => { const i = arr.indexOf(t); return i < 0 ? 99 : i; };
    const groups = d.byTactic || [];
    const band1 = groups.filter(g => BAND1.includes(g.tactic)).sort((a, b) => ordIdx(BAND1, a.tactic) - ordIdx(BAND1, b.tactic));
    const band2 = groups.filter(g => !BAND1.includes(g.tactic)).sort((a, b) => ordIdx(BAND2, a.tactic) - ordIdx(BAND2, b.tactic));
    let html = note + meta;
    if (band1.length) html += `<div class="d3f-band"><div class="d3f-band-h">🛠 Harden now — implement these to prevent, detect and contain a recurrence</div><div class="d3f-actions">${band1.map(d3fGroup).join("")}</div></div>`;
    if (band2.length) html += `<div class="d3f-band"><div class="d3f-band-h d3f-band-h2">🚑 This incident &amp; context — eviction/recovery steps for the live response, plus prerequisites</div><div class="d3f-actions">${band2.map(d3fGroup).join("")}</div></div>`;
    el.innerHTML = html;
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.loadD3fend = loadD3fend;
  window.scheduleD3fendReload = scheduleD3fendReload;
})();
