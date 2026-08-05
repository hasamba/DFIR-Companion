// Four server-derived panels that share one shape (#415 tier 3).
//
// Beacon candidates (#82), evidence gaps (#9), playbook match (#230) and ATT&CK mitigations. Each
// is the same five things: a data cache, a debounce timer, a load(caseId), a schedule…Reload() and
// a render() — the shape js/dashboard-anomalies.js and js/dashboard-sessions.js already use.
//
// ONE MODULE RATHER THAN FOUR, and it is a judgement call worth stating. The repo's convention is
// one module per feature, and these are four features. But they are 12, 42, 60 and 89 lines; four
// files would mean four registrations, four manifest rows and four sets of gates for panels that
// are loaded together by the same fan-out, refreshed by the same WS event, and read-only in the
// same way. Split them if any one of them grows a real interaction surface.
//
// Their state is inside the closure. In a CLASSIC script a top-level `let` joins the shared global
// lexical environment, so unwrapped these caches would still be reachable by name from every other
// script — the measurement that picked these four found ZERO of their bindings read from outside,
// and wrapping is what keeps that true.
//
// No initializer: none of them wires anything at load. The page calls load…() when a case opens.
(function () {

  // ── Beacon Candidates (#82) ───────────────────────────────────────────────────────────
  // Periodic outbound channels (source → dest:port) whose inter-arrival jitter is low enough to
  // look like a C2 callback. Derived server-side (GET /cases/:id/beacon-candidates) from the
  // network events; a hunting lead, NOT a verdict. Worst-first (external + most regular on top).
  let beaconsData = [];
  let beaconsTimer = null;
  function loadBeacons(caseId) {
    fetch(`/cases/${caseId}/beacon-candidates`).then(r => r.json()).then(b => {
      beaconsData = Array.isArray(b) ? b : [];
      renderBeacons();
    }).catch(() => {});
  }
  function scheduleBeaconsReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(beaconsTimer);
    beaconsTimer = setTimeout(() => loadBeacons(caseId), 800);
  }
  function renderBeacons() {
    const el = document.getElementById("beacons");
    if (!el) return;
    if (!beaconsData.length) { el.innerHTML = "<span data-safe-style='color:var(--text-muted)'>No periodic outbound channels detected in the network events.</span>"; return; }
    const rows = beaconsData.map(b => {
      const dest = (b.destPort !== undefined && b.destPort !== null) ? `${esc(b.destIp)}:${esc(b.destPort)}` : esc(b.destIp);
      const when = (b.firstSeen !== b.lastSeen) ? `${esc(b.firstSeen)} → ${esc(b.lastSeen)}` : esc(b.firstSeen || "(undated)");
      const sevColor = KC_SEV_COLOR[b.severity] || "var(--border-color)";
      return `<tr>` +
        `<td><span class="sev-${esc(b.severity)}" data-safe-style="color:${sevColor};font-weight:bold">${esc(b.severity)}</span>${b.external ? " <span data-safe-style='color:var(--text-muted);font-size:10px'>ext</span>" : ""}</td>` +
        `<td>${esc(b.source)}</td>` +
        `<td><code>${dest}</code></td>` +
        `<td title="mean inter-arrival interval">~${esc(b.intervalSeconds)}s</td>` +
        `<td title="interval jitter (stddev as % of mean) — lower is more beacon-like">±${esc(b.jitterSeconds)}s (${esc(b.jitterPct)}%)</td>` +
        `<td>${esc(b.eventCount)}</td>` +
        `<td data-safe-style="color:var(--text-muted);font-size:11px">${when}</td>` +
        `</tr>`;
    }).join("");
    el.innerHTML =
      `<div data-safe-style="color:var(--text-muted);font-size:11px;margin-bottom:6px">Periodic traffic is a hunting lead, not a verdict — legitimate software also polls on a timer. Confirm the destination reputation and the owning process.</div>` +
      `<div class="vql-result-wrap"><table class="vql-result"><thead><tr>` +
      `<th>Severity</th><th>Source</th><th>Destination</th><th>Interval</th><th>Jitter</th><th>Events</th><th>When</th>` +
      `</tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  // Evidence gaps (investigation-guidance #9): what the case is MISSING — uncovered kill-chain phases
  // (each with a where-to-collect directive), silent windows, and lookalike-actor next moves. GET
  // /cases/:id/known-unknowns returns the SAME structured items the synthesis prompt consumes.
  let evidenceGapsData = [];
  let evidenceGapsTimer = null;
  function loadEvidenceGaps(caseId) {
    fetch(`/cases/${caseId}/known-unknowns`).then(r => r.json()).then(j => {
      evidenceGapsData = (j && Array.isArray(j.items)) ? j.items : [];
      renderEvidenceGaps();
    }).catch(() => {});
  }
  function scheduleEvidenceGapsReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(evidenceGapsTimer);
    evidenceGapsTimer = setTimeout(() => loadEvidenceGaps(caseId), 800);
  }
  function renderEvidenceGaps() {
    const el = document.getElementById("evidenceGaps");
    if (!el) return;
    const items = evidenceGapsData || [];
    if (!items.length) { el.innerHTML = "<div class='eg-empty'>No evidence gaps flagged yet — surfaced once the case has a Critical/High finding (run Synthesize).</div>"; return; }
    // Deploy a collect directive only for a KNOWN case host (short-host match) when Velociraptor is
    // configured — reuses the #8 .collect-deploy button + its global delegated click handler.
    const knownHosts = new Set(((DfirState.lastState() && DfirState.lastState().forensicTimeline) || []).map(e => egShortHost(e.asset)).filter(Boolean));
    const collectBtn = (c) => {
      if (!c || !c.host) return "";
      const what = c.logSource || c.artifact || "";
      const summary = `📥 collect ${esc(what)}${what ? " " : ""}from ${esc(c.host)}`;
      const deployable = veloEnabled && knownHosts.has(egShortHost(c.host));
      const btn = deployable
        ? `<button class="collect-deploy" data-host="${escAttr(c.host)}" data-artifact="${escAttr(c.artifact || "")}" data-logsource="${escAttr(c.logSource || "")}" title="Launch this collection on ${escAttr(c.host)} via Velociraptor">⬇ Collect on ${esc(c.host)}</button>`
        : `<span class="collect-manual" title="${veloEnabled ? 'Host not seen in this case — collect manually' : 'Velociraptor API not configured — collect manually'}">manual collection</span>`;
      return `<span class="eg-collect"><span class="eg-what">${summary}</span> ${btn}</span>`;
    };
    el.innerHTML = "<div class='eg-list'>" + items.map(it => {
      if (it.kind === "silence_gap") {
        return `<div class="eg-item eg-gap"><span class="eg-kind">silent window</span><span class="eg-label">${esc(it.label)}</span><br><a class="eg-gaplink" data-act="jumpToGaps">See Timeline Gaps →</a></div>`;
      }
      if (it.kind === "likely_next_technique") {
        return `<div class="eg-item eg-next"><span class="eg-kind">likely next</span><span class="eg-label">${esc(it.label)}</span></div>`;
      }
      if (it.kind === "yield_gap") {
        // Source-yield gap (investigation-guidance #10): a source that was collected but yielded nothing,
        // or a telemetry type with no detector to corroborate it — a blind spot, not a clean source.
        return `<div class="eg-item eg-yield"><span class="eg-kind">blind spot</span><span class="eg-label">${esc(it.label)}</span></div>`;
      }
      if (it.kind === "playbook_step") {
        // Unobserved playbook step (#230): the case follows a published chain but never evidenced
        // this stage — a sharper gap than an uncovered tactic, and it carries the same directive.
        const collects = (it.collect || []).map(collectBtn).join("");
        const ref = (it.playbook && it.playbook.reference)
          ? ` <a class="eg-gaplink" href="${escAttr(it.playbook.reference)}" target="_blank" rel="noopener">playbook source ↗</a>`
          : "";
        return `<div class="eg-item eg-playbook"><span class="eg-kind">unobserved playbook step</span><span class="eg-label">${esc(it.label)}</span>${ref}${collects}</div>`;
      }
      const collects = (it.collect || []).map(collectBtn).join("");
      return `<div class="eg-item"><span class="eg-kind">uncovered phase</span><span class="eg-label">${esc(it.label)}</span>${collects}</div>`;
    }).join("") + "</div>";
  }

  // ── Playbook Match (#230) ──────────────────────────────────────────────────────────────────
  // Adversary Hints above answers "which techniques does this case share with a known group".
  // This answers the harder question: did they happen in the ORDER a published playbook describes.
  // Derived server-side (GET /cases/:id/playbook-match) from the bundled catalog of CISA-documented
  // ransomware chains — offline, no AI. Two rules this renderer exists to keep:
  //   - the caveat renders WITH the match, never as a tooltip. A named group beside a percentage
  //     reads as attribution unless it says plainly that it isn't.
  //   - every matched step is clickable through to the event that evidences it. A step marked
  //     green that the analyst can't verify is worse than no step at all.
  let playbookMatchData = null;
  let playbookMatchTimer = null;
  function loadPlaybookMatch(caseId) {
    fetch(`/cases/${caseId}/playbook-match`).then(r => r.ok ? r.json() : null).then(d => {
      playbookMatchData = (d && typeof d === "object") ? d : null;
      renderPlaybookMatch();
    }).catch(() => {});
  }
  function schedulePlaybookMatchReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(playbookMatchTimer);
    playbookMatchTimer = setTimeout(() => loadPlaybookMatch(caseId), 800);
  }
  function renderPlaybookMatch() {
    const el = document.getElementById("playbookMatch");
    if (!el) return;
    const d = playbookMatchData;
    const caveat = `<div class="pm-caveat">⚠ ${esc((d && d.caveat) || "Sequence similarity to a published playbook — not attribution.")}</div>`;
    if (!d) {
      el.innerHTML = caveat + `<div class="pm-empty">Playbook catalog not available.</div>`;
      return;
    }
    const observed = d.observed || [];
    if (!observed.length) {
      el.innerHTML = caveat + `<div class="pm-empty">No ATT&amp;CK-tagged events in the timeline yet — sequence matching needs a chronology.</div>`;
      return;
    }
    const matches = d.matches || [];
    if (!matches.length) {
      el.innerHTML = caveat + `<div class="pm-empty">No published playbook matches this case's ${esc(observed.length)}-technique sequence at or above ${esc(d.minScore)}%.</div>`;
      return;
    }
    const meta = `<div class="pm-meta">Top ${esc(matches.length)} of the catalog · matched over ${esc(observed.length)} chronological technique(s) · ${esc(d.source || "")}${d.generated ? ` (${esc(d.generated)})` : ""} · a step matches when it appears IN ORDER, allowing unrelated activity in between</div>`;
    const cards = matches.map(m => {
      const scope = m.scope === "host" && m.host
        ? `<span class="pm-scope" title="This chain holds together on one host's slice of the timeline">on ${esc(m.host)}</span>`
        : `<span class="pm-scope" title="This chain holds together across the whole case timeline, spanning hosts">case-wide</span>`;
      const ref = m.reference
        ? `<a class="pm-ref" href="${escAttr(m.reference)}" target="_blank" rel="noopener" title="The public advisory this chain was distilled from">source ↗</a>`
        : "";
      const steps = (m.steps || []).map((s, i) => {
        const cls = s.status === "matched" ? "pm-matched" : s.status === "out-of-order" ? "pm-ooo" : "pm-missing";
        const techUrl = attackUrl(s.step.technique);
        const tech = techUrl
          ? `<a class="pm-step-tech" href="${escAttr(techUrl)}" target="_blank" rel="noopener">${esc(s.step.technique)}</a>`
          : `<span class="pm-step-tech">${esc(s.step.technique)}</span>`;
        const tactic = s.tactic ? `<span class="pm-step-tactic">${esc(s.tactic)}</span>` : "";
        let status;
        if (s.status === "matched") {
          const base = s.matchKind === "base"
            ? ` <span class="pm-base" title="The case tagged a different sub-technique of the same base technique — a partial match">(base only: ${esc(s.matchedTechnique)})</span>`
            : "";
          const jump = s.matchedEventId
            ? ` <button type="button" class="pm-jump" data-act="playbookJumpToEvent" data-id="${escAttr(s.matchedEventId)}" title="Jump to the timeline event that evidences this step">evidence →</button>`
            : "";
          status = `<span class="pm-step-status">✅ matched${base}</span>${jump}`;
        } else if (s.status === "out-of-order") {
          status = `<span class="pm-step-status" title="This technique IS in the case, but not at a point that keeps the chain — check host clocks and collection lag before reading anything into it">🟡 out of order</span>`;
        } else {
          status = `<span class="pm-step-status" title="Never observed — either it did not happen, or the evidence was not collected. See Evidence Gaps for what to collect.">❌ not observed</span>`;
        }
        return `<div class="pm-step ${cls}"><span class="pm-step-n">${esc(i + 1)}</span>${tech}<span class="pm-step-name">${esc(s.step.name)}</span>${tactic}${status}</div>`;
      }).join("");
      const missing = (m.steps || []).filter(s => s.status === "missing");
      const gaps = missing.length
        ? `<div class="pm-gaps">${esc(missing.length)} step(s) of this chain were never evidenced — either they did not happen, or the evidence was not collected. <a class="pm-gaplink" data-act="playbookJumpToGaps">See Evidence Gaps for what to collect →</a></div>`
        : "";
      return `<div class="pm-card">` +
        `<div class="pm-card-head">` +
          `<span class="pm-name">${esc(m.name)}</span>${ref}${scope}` +
          `<span class="pm-score" title="Weighted fraction of the playbook's steps observed in order (exact sub-technique = full credit, base technique = half)">${esc(m.score)}% · ${esc(m.matchedCount)}/${esc((m.steps || []).length)} steps</span>` +
        `</div>` +
        `<div class="pm-desc">${esc(m.description)}</div>` +
        `<div class="pm-steps">${steps}</div>` +
        gaps +
      `</div>`;
    }).join("");
    el.innerHTML = caveat + meta + `<div class="pm-list">${cards}</div>`;
  }

  function loadAttackMitigations(caseId) {
    fetch(`/cases/${caseId}/attack-mitigations`).then(r => r.json()).then(d => {
      mitigationsData = (d && typeof d === "object") ? d : null;
      renderMitigations();
    }).catch(() => {});
  }
  function scheduleAttackMitigationsReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(mitigationsTimer);
    mitigationsTimer = setTimeout(() => loadAttackMitigations(caseId), 800);
  }

  // ── ATT&CK Mitigations (#178) — the concrete "what to do" layer above D3FEND ───────────────
  // For each identified technique, the MITRE ATT&CK mitigations (M-codes) recommended for it,
  // ranked by how many of the case's techniques each one addresses (highest-leverage first).
  // Each carries a concrete, technique-specific action. Offline; derived server-side.
  let mitigationsData = null;
  let mitigationsTimer = null;
  function renderMitigations() {
    const el = document.getElementById("mitigationsPanel");
    if (!el) return;
    const d = mitigationsData;
    // Stay quiet (let the D3FEND block below carry the empty/where-to-get-data messaging) unless
    // there are actual mitigations to show — this block is the "do this" highlight.
    if (!d || !d.mappedTechniqueCount || !d.caseTechniqueCount || !d.coveredTechniqueCount) { el.innerHTML = ""; return; }
    const head = `<div class="mit-h">🎯 Recommended mitigations — concrete ATT&CK actions, highest-leverage first</div>`;
    const meta = `<div class="mit-meta">${esc(d.byMitigation.length)} mitigation(s) covering ${esc(d.coveredTechniqueCount)} of ${esc(d.caseTechniqueCount)} identified technique(s) · MITRE ATT&CK v${esc(d.attackVersion)} · ordered by how many of this case's techniques each one addresses</div>`;
    const COV = 8;
    // One row per mitigation (mirrors the D3FEND row): the name carries the description on hover,
    // and the case technique(s) it applies to sit inline on the same line.
    const rows = (d.byMitigation || []).map(m => {
      const techs = m.techniques || [];
      const shown = techs.slice(0, COV).map(t => {
        const u = attackUrl(t);
        return u ? `<a href="${escAttr(u)}" target="_blank" rel="noopener" class="mit-tech">${esc(t)}</a>` : `<span class="mit-tech">${esc(t)}</span>`;
      }).join("");
      const moreN = techs.length - COV;
      const more = moreN > 0 ? `<span class="mit-more" title="${escAttr(techs.join(", "))}">+${esc(moreN)} more</span>` : "";
      const tip = m.description || "";
      const name = m.url
        ? `<a href="${escAttr(m.url)}" target="_blank" rel="noopener" class="mit-name" title="${escAttr(tip)}">${esc(m.id)} · ${esc(m.name)}</a>`
        : `<span class="mit-name" title="${escAttr(tip)}">${esc(m.id)} · ${esc(m.name)}</span>`;
      const applies = techs.length ? `<span class="mit-covers">applies to ${shown}${more}</span>` : "";
      return `<div class="mit-row">${name}${applies}</div>`;
    }).join("");
    el.innerHTML = head + meta + `<div class="mit-card">${rows}</div>`;
  }

  // AI remediation plan (#178): one text-only call → an incident-specific, prioritized action list,
  // grounded in the case's findings + the deterministic ATT&CK mitigations. Ephemeral (no save).
  function generateRemediation(btn) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const msg = document.getElementById("remediationMsg");
    const out = document.getElementById("remediationPlan");
    btn.disabled = true;
    msg.textContent = "generating… (one AI call)";
    fetch(`/cases/${caseId}/remediation-plan`, { method: "POST" }).then(async r => {
      const j = await r.json().catch(() => ({}));
      if (!r.ok) {
        msg.textContent = j.error || (r.status === 501 ? "AI provider not configured — set one up in Settings → AI." : "Failed (restart the companion server if this endpoint 404s).");
        out.innerHTML = "";
        return;
      }
      msg.textContent = "";
      out.innerHTML = (j.plan && j.plan.trim())
        ? `<div class="rem-h">✨ Incident remediation plan <span class="rem-sub">AI-generated from this case — review before acting</span></div>` + mdToHtml(j.plan)
        : `<p data-safe-style="color:var(--text-muted)">No plan returned.</p>`;
    }).catch(e => { msg.textContent = "error: " + e.message; }).finally(() => { btn.disabled = false; });
  }

  window.loadBeacons = loadBeacons;
  window.scheduleBeaconsReload = scheduleBeaconsReload;
  window.loadEvidenceGaps = loadEvidenceGaps;
  window.scheduleEvidenceGapsReload = scheduleEvidenceGapsReload;
  window.loadPlaybookMatch = loadPlaybookMatch;
  window.schedulePlaybookMatchReload = schedulePlaybookMatchReload;
  window.loadAttackMitigations = loadAttackMitigations;
  // The ACTIONS dispatch table calls this one by name from a click.
  window.generateRemediation = generateRemediation;
  window.scheduleAttackMitigationsReload = scheduleAttackMitigationsReload;
})();
