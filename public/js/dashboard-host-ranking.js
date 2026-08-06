// Host & Account Ranking (#202) — which hosts and accounts the case's evidence touches most, and
// the per-row detail that expands underneath (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the last-fetched ranking, the debounce timer that coalesces
// reload requests, and which row is currently expanded. This is a CLASSIC script, so unwrapped
// those three `let`s would join the shared global lexical environment.
//
// ITS WIRING IS AN INITIALIZER: one delegated click listener on the panel. Delegated rather than
// per-row because the rows are re-rendered on every refresh — but it is still bound at module
// scope, which in a <head> script queries #hostRanking before the markup exists and binds nothing.
(function () {
  // ── Host & Account Ranking (#202) ─────────────────────────────────────────────────────
  // Which hosts/accounts carry the attack — scored by SIGNAL (severity-weighted events +
  // techniques + connective IOCs), not volume, so benign-but-chatty hosts sink. Derived
  // server-side (GET /cases/:id/host-ranking); re-derived (debounced) on each state change.
  let hostRankingData = null;
  let hostRankingTimer = null;
  let hostRankingExpanded = null; // "<type>:<name-lowercased>" of the one open row, or null (#237)
  function loadHostRanking(caseId) {
    fetch(`/cases/${caseId}/host-ranking`)
      .then((r) => r.json())
      .then((d) => {
        hostRankingData = d && typeof d === "object" ? d : null;
        renderHostRanking();
      })
      .catch(() => {});
  }
  function scheduleHostRankingReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(hostRankingTimer);
    hostRankingTimer = setTimeout(() => loadHostRanking(caseId), 800);
  }
  function applyHostRankingScope() {
    const caseId = document.getElementById("caseId").value.trim();
    const w = hostRankingData && hostRankingData.suggestedWindow;
    if (!caseId || !w || !w.start) return;
    fetch(`/cases/${caseId}/scope`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ start: w.start, end: w.end }),
    })
      .then(() => {
        if (typeof refresh === "function") refresh();
      })
      .catch(() => {});
  }
  function renderHostRanking() {
    const el = document.getElementById("hostRanking");
    if (!el) return;
    const d = hostRankingData;
    if (!d || !d.ranks || !d.ranks.length) {
      el.innerHTML = `<div class="hr-empty">No host or account carries attack signal yet — ranking surfaces entities with Critical/High/Medium events, techniques, or connective IOCs.</div>`;
      return;
    }
    const w = d.suggestedWindow || {};
    let scope = "";
    if (d.topHosts && d.topHosts.length && w.start) {
      const fmt = (t) =>
        esc(
          (t || "")
            .replace("T", " ")
            .replace(/\.\d+Z?$/, "")
            .replace("Z", ""),
        );
      scope = `<div class="hr-scope">⌖ Signal concentrated on <b>${esc(d.topHosts.join(", "))}</b> · suggested scope ${fmt(w.start)} → ${fmt(w.end)} <button class="hr-apply" data-act="applyHostRankingScope">Apply scope window</button></div>`;
    }
    const rows = d.ranks
      .map((r) => {
        const key = `${r.type}:${r.name.toLowerCase()}`;
        const isOpen = hostRankingExpanded === key;
        const badges = [
          r.critical
            ? `<span class="hr-badge hr-crit">${esc(r.critical)} Crit</span>`
            : "",
          r.high
            ? `<span class="hr-badge hr-high">${esc(r.high)} High</span>`
            : "",
          r.medium
            ? `<span class="hr-badge hr-med">${esc(r.medium)} Med</span>`
            : "",
          r.techniques
            ? `<span class="hr-tech">${esc(r.techniques)} tech</span>`
            : "",
          r.connectiveIocs
            ? `<span class="hr-conn">⊕${esc(r.connectiveIocs)} IOC</span>`
            : "",
        ]
          .filter(Boolean)
          .join(" ");
        const rowHtml =
          `<div class="hr-row ${r.type === "account" ? "acct" : ""}${isOpen ? " hr-open" : ""}" data-hr-key="${escAttr(key)}">` +
          `<span class="hr-caret">▶</span>` +
          `<span class="hr-name">${esc(r.name)}</span><span class="hr-kind">${esc(r.type)}</span>${badges}<span class="hr-score" title="signal score">${esc(r.score)}</span></div>`;
        const detailHtml = isOpen ? renderHostRankingDetail(r) : "";
        return `<div class="hr-row-wrap">${rowHtml}${detailHtml}</div>`;
      })
      .join("");
    el.innerHTML = scope + `<div class="hr-list">${rows}</div>`;
  }

  // Expanded detail for one ranked host/account (#237): the events that contributed to its
  // score (resolved from the scoped+FP-filtered timeline already on the page — same source the
  // Attack Phases panel uses) and the IOCs connected to it (resolved from the scoped IOC list).
  // Capped at 50 each — a "+N more" note covers the rest, never silently truncated.
  function renderHostRankingDetail(r) {
    const caseId = document.getElementById("caseId").value.trim();
    const evById = new Map(
      (DfirState.lastFt() || []).map((e) => [String(e.id), e]),
    );
    const events = (r.eventIds || [])
      .map((id) => evById.get(String(id)))
      .filter(Boolean)
      .sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
    const iocById = new Map((lastIocs || []).map((i) => [String(i.id), i]));
    const iocs = (r.iocIds || [])
      .map((id) => iocById.get(String(id)))
      .filter(Boolean);

    const EV_CAP = 50,
      IOC_CAP = 50;
    const evShown = events.slice(0, EV_CAP);
    const iocShown = iocs.slice(0, IOC_CAP);

    const evHtml = evShown.length
      ? evShown
          .map((e) => {
            const desc = String(e.description || "");
            const trunc = desc.length > 140 ? desc.slice(0, 140) + "…" : desc;
            return (
              `<a class="ev-jump hr-det-event" href="${escAttr(eventDeepLink(caseId, e.id))}" data-evid="${escAttr(e.id)}" title="Jump to this event in the timeline">` +
              `<span class="hr-det-time sev-${esc(e.severity)}">${esc(e.timestamp || "(undated)")}</span>` +
              `<span class="hr-det-desc">${esc(trunc)}</span></a>`
            );
          })
          .join("")
      : `<div class="hr-det-empty">No events</div>`;
    const evMore =
      events.length > EV_CAP
        ? `<div class="hr-det-more">+${events.length - EV_CAP} more event${events.length - EV_CAP === 1 ? "" : "s"}</div>`
        : "";

    const iocHtml = iocShown.length
      ? iocShown
          .map((i) => {
            const verdict = worstIocVerdict(i);
            const dot = `<span class="hr-det-dot"${verdict ? ` data-safe-style="background:${verdictColor(verdict)}" title="${esc(verdict)}"` : ""}></span>`;
            return `<div class="hr-det-ioc">${dot}<span class="hr-det-ioc-type">${esc(i.type)}</span><span class="hr-det-ioc-val">${esc(i.value)}</span></div>`;
          })
          .join("")
      : `<div class="hr-det-empty">No IOCs</div>`;
    const iocMore =
      iocs.length > IOC_CAP
        ? `<div class="hr-det-more">+${iocs.length - IOC_CAP} more IOC${iocs.length - IOC_CAP === 1 ? "" : "s"}</div>`
        : "";

    return (
      `<div class="hr-detail">` +
      `<div class="hr-det-col"><div class="hr-det-head">Events (${events.length})</div><div class="hr-det-list">${evHtml}${evMore}</div></div>` +
      `<div class="hr-det-col"><div class="hr-det-head">IOCs (${iocs.length})</div><div class="hr-det-list">${iocHtml}${iocMore}</div></div>` +
      `</div>`
    );
  }

  // Expand/collapse a host/account row to reveal its events + IOCs (single-open accordion —
  // opening one closes any other open row). Event-delegated on the persistent #hostRanking
  // container so it survives renderHostRanking() re-renders (mirrors the Attack Phases pattern
  // at the #phases click listener).

  // Adversary Hints (#46) moved to js/dashboard-adversary-hints.js (#415 tier 3). No
  // initializer: nothing here runs at load, and the per-technique hunt buttons are wired by
  // the renderer. A missing file is reported through DfirFacade.filled, below.

  // The delegated row listener the inline block bound at module scope.
  function initHostRanking() {
    document
      .getElementById("hostRanking")
      .addEventListener("click", function (e) {
        const row = e.target.closest(".hr-row");
        if (!row) return;
        const key = row.getAttribute("data-hr-key");
        hostRankingExpanded = hostRankingExpanded === key ? null : key;
        renderHostRanking();
      });
  }

  window.loadHostRanking = loadHostRanking;
  window.scheduleHostRankingReload = scheduleHostRankingReload;
  window.applyHostRankingScope = applyHostRankingScope;
  window.initHostRanking = initHostRanking;
})();
