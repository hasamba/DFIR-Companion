// Gap Hypotheses (#96) — what the evidence does NOT show, and which artefact would settle each
// open question (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the severity colour table and the artefact index the rows
// render titles from. In a CLASSIC script an unwrapped top-level binding joins the shared global
// lexical environment, so `GH_SEV_COLOR` alone would be a page-wide global named after this panel.
//
// NO INITIALIZER: nothing here runs at load, and nothing outside binds one of these functions while
// the page parses.
(function () {
  // ── Gap Hypotheses (#96) ──────────────────────────────────────────────────────────────
  // AI hypotheses for the timeline's silent periods + the DETERMINISTIC shadow-artifact
  // collections that reconstruct each missing window. On-demand (an AI call, so it does NOT
  // auto-load like the gaps table above): the analyst clicks "Hypothesize gaps", reviews each
  // gap's hypothesis of what the attacker did, then copies/deploys a shadow-artifact collection
  // (USN journal, SRUM, Prefetch, Amcache, …) via the shared launchHuntInto() (POST
  // /velociraptor/hunt). Ephemeral — not persisted. A hypothesis is a lead, not proof.
  const GH_SEV_COLOR = {
    Critical: "#ff5c5c",
    High: "#ff9f43",
    Medium: "#ffd93b",
    Low: "#6bcb77",
    Info: "#6aa9ff",
  };
  let ghArtMeta = []; // index → { title } for the deploy description (the textarea holds the editable VQL)

  function resetGapHypotheses() {
    const el = document.getElementById("gapHypotheses");
    if (el) el.innerHTML = "";
    const msg = document.getElementById("hypothesizeGapsMsg");
    if (msg) msg.textContent = "";
  }

  function doHypothesizeGaps() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const btn = document.getElementById("hypothesizeGapsBtn");
    const msg = document.getElementById("hypothesizeGapsMsg");
    const el = document.getElementById("gapHypotheses");
    if (!el) return;
    if (btn) btn.disabled = true;
    if (msg) msg.textContent = "thinking… (one AI call over the flagged gaps)";
    el.innerHTML = "";
    fetch(`/cases/${caseId}/timeline-gaps/hypothesize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          if (msg) msg.textContent = "";
          el.innerHTML = `<div class="gh-empty" data-safe-style="color:var(--sev-high)">error: ${esc(j.error || "could not generate hypotheses")} — restart the companion server if this 404s</div>`;
          return;
        }
        renderGapHypotheses(j);
        const n = (j.hypotheses || []).length;
        if (msg) msg.textContent = n ? `${n} gap(s) analysed` : "";
      })
      .catch((e) => {
        if (msg) msg.textContent = "";
        el.innerHTML = `<div class="gh-empty" data-safe-style="color:var(--sev-high)">error: ${esc(e.message)}</div>`;
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }

  function renderGapHypotheses(result) {
    const el = document.getElementById("gapHypotheses");
    if (!el) return;
    const hyps = (result && result.hypotheses) || [];
    if (!hyps.length) {
      el.innerHTML = `<div class="gh-empty">No flagged gaps to hypothesise about — the timeline shows no suspicious silent periods (or none cleared the thresholds).</div>`;
      return;
    }
    ghArtMeta = [];
    const caveat = `<div class="gh-caveat">⚠ ${esc(result.caveat || "AI hypotheses are leads, not proof — confirm by collecting the shadow artifacts and correlating.")}${veloEnabled ? "" : " The Velociraptor API is not configured, so Deploy is disabled — copy the VQL to run it yourself."}</div>`;
    const cards = hyps
      .map((h, gi) => {
        const g = h.gap || {};
        const sev = h.severity || g.severity || "Medium";
        const sevColor = GH_SEV_COLOR[sev] || "#9aa4b2";
        const sevBadge = `<span class="gh-sev" data-safe-style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}55">${esc(sev)}</span>`;
        const kind = g.complete ? "complete silence" : "partial gap";
        const conf =
          typeof h.confidence === "number" && h.confidence > 0
            ? `<span class="gh-conf">confidence ${esc(h.confidence)}%</span>`
            : "";
        const when = `<div class="gh-when">${esc(g.durationLabel || "")} · ${esc(g.startTimestamp || "")} → ${esc(g.endTimestamp || "")}</div>`;
        const hyp = h.hypothesis
          ? `<div class="gh-hyp">${esc(h.hypothesis)}</div>`
          : `<div class="gh-hyp" data-safe-style="color:var(--text-muted)">The AI did not propose a hypothesis for this gap — collect the shadow artifacts below to reconstruct the window.</div>`;
        const actions =
          h.attackerActions && h.attackerActions.length
            ? `<ul class="gh-actions-list">${h.attackerActions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul>`
            : "";
        const techs = (h.mitreTechniques || [])
          .map((t) => {
            const u = attackUrl(t);
            return u
              ? `<a href="${escAttr(u)}" target="_blank" rel="noopener" class="gh-tech">${esc(t)}</a>`
              : `<span class="gh-tech">${esc(t)}</span>`;
          })
          .join("");
        const techRow = techs ? `<div class="gh-techs">${techs}</div>` : "";
        const recSet = new Set(h.recommendedArtifactIds || []);
        const hosts =
          h.targetHosts && h.targetHosts.length
            ? `collect from: ${h.targetHosts.join(", ")}`
            : "no specific host identified from the surrounding events — scope the collection manually or run it fleet-wide";
        // Recommended (AI-prioritised) artifacts first, then the rest of the catalog.
        const arts = [...(h.shadowArtifacts || [])].sort(
          (a, b) => (recSet.has(b.id) ? 1 : 0) - (recSet.has(a.id) ? 1 : 0),
        );
        const artCards = arts
          .map((a) => {
            const idx = ghArtMeta.length;
            ghArtMeta.push({
              title: `Shadow artifact: ${a.name} (${g.id || "gap"})`,
            });
            const rec = recSet.has(a.id);
            const recBadge = rec
              ? `<span class="gh-art-rec-badge" title="The AI judged this artifact most relevant to this gap">recommended</span>`
              : "";
            const deployBtn = veloEnabled
              ? `<button class="gh-deploy" data-idx="${idx}" title="Collect this artifact across all enrolled Velociraptor clients (scope to the host(s) above as needed)">▶ Deploy collection</button>`
              : `<button class="gh-deploy" disabled title="Velociraptor API not configured — set the API config path in Settings → Integrations, then restart the server">▶ Deploy collection</button>`;
            return (
              `<div class="gh-art${rec ? " gh-art-rec" : ""}">` +
              `<div class="gh-art-head"><span class="gh-art-name">${esc(a.name)}</span>${recBadge}<span class="gh-conf">${esc(a.velociraptorArtifact)}</span></div>` +
              `<div class="gh-art-why">${esc(a.reconstructs)}</div>` +
              `<textarea class="gh-vql" id="ghQ${idx}" spellcheck="false">${esc(a.vql)}</textarea>` +
              `<div class="gh-art-actions"><button class="gh-copy" data-idx="${idx}">Copy VQL</button>${deployBtn}</div>` +
              `<div class="gh-res" id="ghRes${idx}"></div>` +
              `</div>`
            );
          })
          .join("");
        return (
          `<div class="gh-card">` +
          `<div class="gh-head"><span class="gh-title">${esc(g.id || "gap " + (gi + 1))}: ${esc(kind)}</span>${sevBadge}${conf}</div>` +
          when +
          hyp +
          actions +
          techRow +
          `<div class="gh-shadow-head">🛡 Shadow artifacts to reconstruct this window</div>` +
          `<div class="gh-hosts">${esc(hosts)}</div>` +
          artCards +
          `</div>`
        );
      })
      .join("");
    el.innerHTML = caveat + `<div class="gh-list">${cards}</div>`;
    el.querySelectorAll(".gh-copy").forEach(
      (b) =>
        (b.onclick = () => {
          const q = document.getElementById("ghQ" + b.dataset.idx);
          navigator.clipboard
            .writeText(q ? q.value : "")
            .then(() => {
              b.textContent = "Copied ✓";
              b.classList.add("copied");
              setTimeout(() => {
                b.textContent = "Copy VQL";
                b.classList.remove("copied");
              }, 1500);
            })
            .catch(() => {
              b.textContent = "copy failed";
            });
        }),
    );
    el.querySelectorAll(".gh-deploy:not([disabled])").forEach(
      (b) =>
        (b.onclick = () => {
          const idx = b.dataset.idx;
          const q = document.getElementById("ghQ" + idx);
          const title =
            (ghArtMeta[idx] && ghArtMeta[idx].title) ||
            "DFIR shadow-artifact collection";
          launchHuntInto(
            q ? q.value : "",
            title,
            document.getElementById("ghRes" + idx),
            b,
          );
        }),
    );
  }

  window.doHypothesizeGaps = doHypothesizeGaps;
  window.resetGapHypotheses = resetGapHypotheses;
})();
