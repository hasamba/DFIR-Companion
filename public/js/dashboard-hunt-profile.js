// Hunting Profile (#157) — the per-case hunt feedback loop, read-only (#415 tier 3).
//
// Every hunt deployed in this case (flow / playbook / technique / bundle) with whether it found new
// evidence. Auto-loaded on case open and refreshed on the velo_hunt_changed WS event; the server
// does the aggregating in buildHuntingProfile().
//
// NO INITIALIZER, and that is not an oversight. Both functions only touch the DOM when the page
// calls them — there is no load-time wiring here to defer, unlike js/dashboard-tickets.js or
// js/dashboard-mcp.js. The per-row Collect buttons are wired inside renderHuntProfile, at the point
// the rows are created, which is where they have to be.
//
// STATE IS ONE FROZEN LOOKUP. HP_STATUS is a label/colour table, not mutable state, so this module
// has nothing that could escape — the extraction measured zero escaping bindings, the only
// candidate on the board with none.
//
// Depends on esc/escAttr (js/dashboard-escape.js), attackUrl (js/dashboard-ioc.js) and
// renderVqlRows (js/dashboard-fragments.js) — all tier-1 helpers tagged ahead of this file.
(function () {

  // ── Hunting Profile (#157) ────────────────────────────────────────────────────────────
  // The per-case hunt feedback loop, surfaced read-only: every hunt deployed in this case (fleet /
  // playbook / technique / bundle) with whether it found new evidence. Auto-loaded on case open and
  // refreshed on the velo_hunt_changed WS event (deploy + collect both broadcast it). GET returns
  // buildHuntingProfile(): { total, hit, missed, pending, hunts[] }.
  const HP_STATUS = {
    collectedHit: { cls: "hp-hit", label: "hit" },
    collectedMiss: { cls: "hp-miss", label: "no evidence" },
    // #803: a live snapshot (a compiled Sigma rule over pslist()/netstat()/glob()) that returned
    // nothing. Not a miss: the process may have exited before the hunt ran.
    snapshotEmpty: { cls: "hp-pending", label: "empty snapshot" },
    pending: { cls: "hp-pending", label: "pending" },
  };
  function loadHuntProfile(caseId) {
    const el = document.getElementById("huntProfile");
    if (!el) return;
    if (!caseId) { el.innerHTML = `<div class="hp-empty">—</div>`; return; }
    fetch(`/cases/${encodeURIComponent(caseId)}/hunt-outcomes`)
      .then((r) => r.ok ? r.json() : null)
      .then((p) => renderHuntProfile(p))
      .catch(() => { el.innerHTML = `<div class="hp-empty" data-safe-style="color:var(--sev-high)">could not load the hunting profile — restart the companion server if this 404s</div>`; });
  }
  function renderHuntProfile(profile) {
    const el = document.getElementById("huntProfile");
    if (!el) return;
    const hunts = (profile && Array.isArray(profile.hunts)) ? profile.hunts : [];
    if (!hunts.length) {
      el.innerHTML = `<div class="hp-empty">No hunts deployed in this case yet. Deploy a suggested fleet/playbook hunt or run a triage bundle, then collect its results — outcomes show here and feed the next round of suggestions.</div>`;
      return;
    }
    const tally = `<div class="hp-tally">`
      + `<span><b>${profile.total}</b> hunted</span>`
      + `<span data-safe-style="color:#6bcb77"><b>${profile.hit}</b> hit</span>`
      + `<span><b>${profile.missed}</b> no results</span>`
      + (profile.snapshotEmpty ? `<span title="Live-snapshot hunts (compiled Sigma rules) that returned nothing — not negative evidence"><b>${profile.snapshotEmpty}</b> empty snapshot${profile.snapshotEmpty === 1 ? "" : "s"}</span>` : "")
      + `<span data-safe-style="color:#6aa9ff"><b>${profile.pending}</b> pending</span>`
      + `</div>`;
    // Pivot-class productivity (#72): which pivot type (hash/process/path/network/registry) has
    // actually found evidence in this case — the same aggregate signal fed into the hunt-suggestion
    // prompt, surfaced here so the analyst can see why the model is favoring/avoiding a class.
    const pivots = (profile.pivotProductivity || []).filter((p) => p.hit + p.missed > 0);
    const pivotsBlock = pivots.length ? `<div class="hp-pivots">` + pivots.map((p) => {
      const collected = p.hit + p.missed;
      const rate = Math.round((p.hit / collected) * 100);
      const rateCls = rate >= 50 ? "" : " hp-pivot-rate-low";
      return `<span class="hp-pivot" title="${escAttr(`${p.hit}/${collected} hunts found evidence${p.pending ? `, ${p.pending} pending` : ""}`)}">`
        + `<span class="hp-pivot-type">${esc(p.type)}</span>`
        + `<span class="hp-pivot-rate${rateCls}">${p.hit}/${collected} (${rate}%)</span>`
        + `</span>`;
    }).join("") + `</div>` : "";
    const rows = hunts.map((h, i) => {
      const st = h.status === "collected"
        ? (h.foundEvidence ? HP_STATUS.collectedHit : h.coverage === "snapshot" ? HP_STATUS.snapshotEmpty : HP_STATUS.collectedMiss)
        : HP_STATUS.pending;
      // "not collected yet" not "results not yet collected": ▸ results can show LIVE rows from Velociraptor
      // before the hunt is imported, and "results not yet collected" read as a contradiction next to them.
      const result = h.status === "collected"
        ? (h.foundEvidence ? (h.resultSummary || "new evidence") : h.coverage === "snapshot" ? "no rows in the live snapshot (not a miss)" : (h.resultSummary || "no results"))
        : "not collected yet";
      const techs = (h.mitreTechniques || []).map((t) => {
        const u = attackUrl(t);
        return u ? `<a href="${escAttr(u)}" target="_blank" rel="noopener" class="hp-tech">${esc(t)}</a>` : `<span class="hp-tech">${esc(t)}</span>`;
      }).join(" ");
      // #80: what's new vs THIS hunt's previous run (a re-deploy of the same VQL), not the whole case —
      // only set once a second run of the same fingerprint has actually been collected.
      const runDiffBadge = (() => {
        const rd = h.runDiff;
        if (!rd || rd.isFirstRun) return "";
        const parts = [];
        if (rd.addedRows > 0) parts.push(`+${rd.addedRows} row${rd.addedRows === 1 ? "" : "s"}`);
        if ((rd.addedHosts || []).length) parts.push(`${rd.addedHosts.length} new host${rd.addedHosts.length === 1 ? "" : "s"}`);
        if (!parts.length) return ` <span class="hp-rundiff" title="No new rows or hosts since this hunt's previous run">= vs last run</span>`;
        const title = (rd.addedHosts || []).length ? `New hosts since last run: ${rd.addedHosts.join(", ")}` : "New rows since this hunt's previous run";
        return ` <span class="hp-rundiff" title="${escAttr(title)}">↻ ${esc(parts.join(", "))} vs last run</span>`;
      })();
      // Any hunt with a Velociraptor hunt id stays collectible — fleet results trickle in as clients
      // check in, so the button REMAINS after a collect so the analyst can re-pull stragglers (counts
      // accumulate; a hit is never downgraded). Pending → "Collect now"; collected → "Re-collect".
      const collectLabel = h.status === "collected" ? "↻ Re-collect" : "↻ Collect now";
      const collectBtn = h.huntId
        ? ` <button class="hp-collect" data-hid="${escAttr(h.huntId)}" title="Pull this hunt's results now and record what it found (re-pulls stragglers; results trickle in as endpoints check in)">${collectLabel}</button>`
        : "";
      // Expand to view the hunt's actual result rows on demand (fetched from the persisted job) — so the
      // persistent profile can show what a hunt found even after the ephemeral suggestion card is gone.
      const resultsToggle = h.huntId
        ? ` <button class="hp-toggle" data-hid="${escAttr(h.huntId)}" data-idx="${i}"${h.status === "collected" ? "" : ' data-pending="1"'} title="Show this hunt's result rows">▸ results</button>`
        : "";
      return `<div class="hp-item">`
        + `<div class="hp-row">`
        + `<span class="hp-status ${st.cls}">${st.label}</span>`
        + `<span class="hp-src">${esc(h.source || "")}</span>`
        + `<span class="hp-title">${esc(h.title || "(untitled hunt)")}</span>`
        + `<span class="hp-result">— ${esc(result)}</span>`
        + runDiffBadge
        + (techs ? ` ${techs}` : "")
        + resultsToggle
        + collectBtn
        + `</div>`
        + `<div class="hp-detail" id="hpDetail${i}" hidden></div>`
        + `</div>`;
    }).join("");
    el.innerHTML = tally + pivotsBlock + `<div class="hp-list">${rows}</div>`;
    const caseId = document.getElementById("caseId").value.trim();
    // Collect (import) a hunt's results into the case + record the outcome. On success (202) the
    // velo_hunt_changed WS event re-renders the panel; only an error restores the button + flags it.
    const collectHunt = (huntId, btn) => {
      if (!caseId || !huntId) return;
      const label = btn.textContent;
      btn.disabled = true; btn.textContent = "collecting…";
      fetch(`/cases/${encodeURIComponent(caseId)}/velociraptor/collect`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ huntId }) })
        .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
        // `queued` = a collect was already running for this hunt, so this click was folded into a
        // follow-up pass that starts when it finishes (#195). It WILL run — just not this instant.
        .then(({ ok, j }) => {
          if (!ok) { btn.disabled = false; btn.textContent = label; btn.title = (j && j.error) || "collect failed — the hunt may have aged out of Velociraptor's job list"; btn.classList.add("hp-collect-err"); }
          else if (j && j.queued) { btn.textContent = "queued…"; btn.title = "a collect is already running for this hunt — this one runs right after it"; }
        })
        .catch((e) => { btn.disabled = false; btn.textContent = label; btn.title = "collect failed: " + e.message; btn.classList.add("hp-collect-err"); });
    };
    el.querySelectorAll(".hp-collect").forEach((b) => b.onclick = () => collectHunt(b.dataset.hid, b));
    el.querySelectorAll(".hp-toggle").forEach((b) => b.onclick = () => {
      const detail = document.getElementById("hpDetail" + b.dataset.idx);
      if (!detail) return;
      if (!detail.hasAttribute("hidden")) { detail.setAttribute("hidden", ""); b.textContent = "▸ results"; return; }
      detail.removeAttribute("hidden"); b.textContent = "▾ results";
      if (detail.dataset.loaded) return;   // fetched already this render — don't re-pull on every toggle
      if (!caseId) return;
      const hid = b.dataset.hid;
      const pending = !!b.dataset.pending;   // hunt not imported into the case yet
      detail.innerHTML = "<div data-safe-style='color:var(--text-muted);font-size:12px'>loading results…</div>";
      fetch(`/cases/${encodeURIComponent(caseId)}/velociraptor/hunt-rows`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ huntId: hid }) })
        .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
        .then(({ ok, j }) => {
          if (!ok || j.error) { detail.innerHTML = `<div data-safe-style="color:var(--sev-high);font-size:12px">${esc(j.error || "could not load results")}</div>`; return; }
          const n = (j.rows || []).length;
          // These rows are read LIVE from Velociraptor — they are NOT in the case until collected. When the
          // hunt is still pending, say so + offer an inline Collect so the live preview ≠ "imported" is clear.
          const note = (pending && n)
            ? `<div class="hp-preview-note">⚠ Live preview from Velociraptor — these ${n} result(s) are <b>not imported into the case yet</b>. <button class="hp-collect-inline" data-hid="${escAttr(hid)}">↻ Collect now to import</button></div>`
            : "";
          detail.innerHTML = note + (n ? renderVqlRows(j) : "<div data-safe-style='color:var(--text-muted);font-size:12px'>no rows (the hunt may still be collecting, or returned nothing)</div>");
          const ib = detail.querySelector(".hp-collect-inline");
          if (ib) ib.onclick = () => collectHunt(ib.dataset.hid, ib);
          detail.dataset.loaded = "1";
        })
        .catch((e) => { detail.innerHTML = `<div data-safe-style="color:var(--sev-high);font-size:12px">error: ${esc(e.message)} — restart the companion server if this 404s</div>`; });
    });
  }

  window.loadHuntProfile = loadHuntProfile;
})();
