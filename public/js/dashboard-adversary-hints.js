// Adversary Hints (#46) — which known actor's tradecraft the case's ATT&CK coverage resembles, and
// the hunt you can launch straight from a technique (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the last-fetched hint set and the debounce timer that
// coalesces reload requests. This is a CLASSIC script, so unwrapped those two `let`s would join the
// shared global lexical environment and be reachable by name from every other script on the page.
//
// NO INITIALIZER, and that is measured rather than assumed: nothing in this block runs at load, and
// nothing outside it binds one of these functions as the page parses. The per-technique hunt
// buttons are wired inside the renderer, at the point the rows are created, which is where they
// have to be.
(function () {
  // ── Adversary Hints (#46) ─────────────────────────────────────────────────────────────
  // Known ATT&CK groups ranked by technique overlap with the case — offline hypothesis fuel,
  // NOT attribution. Derived server-side (GET /cases/:id/adversary-hints) from the bundled MITRE
  // Groups dataset; re-derived (debounced) on each state change, like the phases panel.
  let adversaryHintsData = null;
  let adversaryHintsTimer = null;
  function loadAdversaryHints(caseId) {
    fetch(`/cases/${caseId}/adversary-hints`)
      .then((r) => r.json())
      .then((d) => {
        adversaryHintsData = d && typeof d === "object" ? d : null;
        renderAdversaryHints();
      })
      .catch(() => {});
  }
  function scheduleAdversaryHintsReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(adversaryHintsTimer);
    adversaryHintsTimer = setTimeout(() => loadAdversaryHints(caseId), 800);
  }
  function renderAdversaryHints() {
    const el = document.getElementById("adversaryHints");
    if (!el) return;
    const d = adversaryHintsData;
    const caveat = `<div class="adv-caveat">⚠ ${esc((d && d.caveat) || "Statistical similarity based on technique overlap — not attribution.")}</div>`;
    if (!d || !d.groupCount) {
      el.innerHTML =
        caveat +
        `<div class="adv-empty">Adversary-group dataset not available — run <code>npm run data:update-attack</code>.</div>`;
      return;
    }
    if (!d.caseTechniqueCount) {
      el.innerHTML =
        caveat +
        `<div class="adv-empty">No techniques identified yet — adversary hints need at least one ATT&CK technique.</div>`;
      return;
    }
    if (!d.hints || !d.hints.length) {
      el.innerHTML =
        caveat +
        `<div class="adv-empty">No group reaches the ${esc(d.minOverlap)}-technique overlap threshold across the case's ${esc(d.caseTechniqueCount)} identified technique(s).</div>`;
      return;
    }
    const meta = `<div class="adv-meta">Top ${esc(d.hints.length)} of ${esc(d.groupCount)} groups · scored over ${esc(d.caseTechniqueCount)} case technique(s) · MITRE ATT&CK v${esc(d.attackVersion)} · <strong>bold</strong> = exact sub-technique match (stronger), dim = base-technique match</div>`;
    const cards = d.hints
      .map((h) => {
        const aliases =
          h.aliases && h.aliases.length
            ? `<span class="adv-aliases">aka ${esc(h.aliases.join(", "))}</span>`
            : "";
        const ratio = `${esc(h.overlapCount)} / ${esc(h.groupTechniqueCount)}`;
        const exactSet = new Set(h.exactTechniques || []);
        const exactBadge = h.exactCount
          ? `<span class="adv-exact" title="${escAttr(h.exactCount)} exact sub-technique match(es) — the strong signal">${esc(h.exactCount)} exact</span>`
          : "";
        const techs = (h.overlapTechniques || [])
          .map((t) => {
            const u = attackUrl(t);
            const cls = exactSet.has(t)
              ? "adv-tech adv-tech-exact"
              : "adv-tech adv-tech-base";
            return u
              ? `<a href="${escAttr(u)}" target="_blank" rel="noopener" class="${cls}">${esc(t)}</a>`
              : `<span class="${cls}">${esc(t)}</span>`;
          })
          .join("");
        const desc = h.description
          ? `<div class="adv-desc">${esc(h.description)}</div>`
          : "";
        return (
          `<div class="adv-card">` +
          `<div class="adv-card-head">` +
          `<a href="${escAttr(h.url)}" target="_blank" rel="noopener" class="adv-name">${esc(h.id)} ${esc(h.name)}</a>` +
          aliases +
          `<span class="adv-score" title="${escAttr(h.overlapCount)} of the case's techniques overlap this group (${escAttr(h.exactCount)} exact sub-technique), of ${escAttr(h.groupTechniqueCount)} it is known to use">⊕ ${ratio}</span>` +
          exactBadge +
          `</div>` +
          desc +
          `<div class="adv-techs">${techs}</div>` +
          `</div>`
        );
      })
      .join("");
    // Adversary emulation (#121): the matched groups' techniques the case hasn't observed yet —
    // predictive hunt priorities. Only present when at least one group matched (server-derived).
    const next =
      d.nextTechniques && d.nextTechniques.length
        ? (() => {
            const matchedTotal = (d.hints || []).length;
            const rows = d.nextTechniques
              .map((n) => {
                const u = n.url || attackUrl(n.id);
                const tech = u
                  ? `<a href="${escAttr(u)}" target="_blank" rel="noopener" class="adv-next-tech">${esc(n.id)}</a>`
                  : `<span class="adv-next-tech">${esc(n.id)}</span>`;
                const nm = n.name
                  ? `<span class="adv-next-name">${esc(n.name)}</span>`
                  : "";
                const groupNames = (n.groups || [])
                  .map((g) => `${g.id} ${g.name}`)
                  .join(", ");
                const support = `<span class="adv-next-support" title="${escAttr(groupNames)}">${esc(n.groupCount)} of ${esc(matchedTotal)} matched groups</span>`;
                // Distinctiveness: lower global prevalence = rarer across ALL groups = more telling a signal.
                const pct =
                  typeof n.prevalence === "number"
                    ? Math.round(n.prevalence * 100)
                    : null;
                const rare =
                  pct === null
                    ? ""
                    : `<span class="adv-next-rare" title="Used by ${esc(pct)}% of all known groups — lower is more distinctive to this actor profile">${esc(pct)}% of groups</span>`;
                // "Where to look" hint, only when the dataset carries data sources (ATT&CK <v17 model).
                const ds =
                  n.dataSources && n.dataSources.length
                    ? `<div class="adv-next-ds" title="ATT&CK data sources — telemetry to hunt in for this technique">🔍 ${esc(n.dataSources.join(" · "))}</div>`
                    : "";
                // A targeted hunt: hand this technique to the AI Fleet-Hunts feature to generate a VQL query.
                const huntBtn = `<button type="button" class="adv-next-hunt" data-act="huntForTechnique" data-id="${escAttr(n.id)}" title="Generate a Velociraptor VQL hunt for this technique (one AI call)">⌖ hunt this</button>`;
                return `<div class="adv-next-row">${tech}${nm}<span class="adv-next-tactic">${esc(n.tactic)}</span>${rare}${support}${huntBtn}</div>${ds}`;
              })
              .join("");
            return (
              `<div class="adv-next">` +
              `<div class="adv-next-h">⌖ Likely next techniques — hunt priorities</div>` +
              `<div class="adv-next-sub">Techniques the matched groups above are known to use that this case hasn't observed yet, ranked by <strong>distinctiveness</strong> (how many matched groups use each × how rare it is across all groups) so generic tradecraft is filtered out — hypothesis fuel for focused hunting, not attribution or a forecast.</div>` +
              `<div class="adv-next-list">${rows}</div>` +
              `</div>`
            );
          })()
        : "";
    el.innerHTML =
      caveat + meta + `<div class="adv-list">${cards}</div>` + next;
  }

  // ATT&CK Mitigations (#178) moved to js/dashboard-derived-panels.js (#415 tier 3).

  // Adversary emulation (#121): turn a "likely next technique" into a runnable, fleet-wide
  // Velociraptor VQL hunt (one AI call). Results render in the Suggested Fleet Hunts panel below,
  // reusing its review + deploy flow. The technique name is looked up from the loaded data (not
  // passed through the inline handler) to avoid attribute-escaping pitfalls.
  function huntForTechnique(techId, btn) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !techId) return;
    const info = (
      (adversaryHintsData && adversaryHintsData.nextTechniques) ||
      []
    ).find((n) => n.id === techId);
    const techniqueName = info && info.name ? info.name : "";
    const msg = document.getElementById("suggestHuntsMsg");
    const panel = document.getElementById("veloHuntSuggest");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "⌖ hunting…";
    }
    if (msg) msg.textContent = `generating a hunt for ${techId}… (one AI call)`;
    vhsSource = "technique"; // #157 adversary-emulation technique hunt
    fetch(`/cases/${caseId}/adversary-hints/hunt-technique`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ techniqueId: techId, techniqueName }),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          if (msg) msg.textContent = "";
          if (panel)
            panel.innerHTML = `<div class="vhs-empty" data-safe-style="color:var(--sev-high)">error: ${esc(j.error || "could not generate a hunt")} — restart the companion server if this 404s</div>`;
          return;
        }
        renderVeloHuntSuggest(j.suggestions || []);
        if (msg)
          msg.textContent = (j.suggestions || []).length
            ? `${j.suggestions.length} hunt(s) for ${techId} — review below ↓`
            : `no hunt generated for ${techId}`;
        const sec = document.getElementById("sec-velohunts");
        if (sec) sec.scrollIntoView({ behavior: "smooth", block: "start" });
      })
      .catch((e) => {
        if (msg) msg.textContent = "";
        if (panel)
          panel.innerHTML = `<div class="vhs-empty" data-safe-style="color:var(--sev-high)">error: ${esc(e.message)}</div>`;
      })
      .finally(() => {
        if (btn) {
          btn.disabled = false;
          btn.textContent = "⌖ hunt this";
        }
      });
  }

  window.loadAdversaryHints = loadAdversaryHints;
  window.scheduleAdversaryHintsReload = scheduleAdversaryHintsReload;
  window.huntForTechnique = huntForTechnique;
})();
