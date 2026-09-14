// Kerberoast chain (#930 item 6).
//
// Per service account a ticket request (4769) names: the requests (RC4 is an offline-cracking-
// compatible type the KDC used — the record does not say who chose it), the baseline before the
// earliest RC4 request, every later row where the EXACT account acts (a name with a compatible
// realm; a bare name is a candidate), and a same-observed-address facet. Whether a ticket was
// cracked is not in any row and is never said.
//
// An IIFE for the same reason as js/dashboard-custody.js: this feature owns state.
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  let chain = { accounts: [], toolLeads: [], gaps: [], excluded: {}, generated: "" };
  let currentCaseId = "";
  let loadGen = 0;
  let status = "loading"; // "loading" | "loaded" | "error": a failed request is never an empty case

  function useRow(u) {
    const same = u.sameObservedAddress
      ? `${esc(u.sameObservedAddress.useAddress)} (this host) and ${esc(u.sameObservedAddress.requestAddress)} (seen by ${esc(u.sameObservedAddress.requestObserver)}, request <code>${esc(u.sameObservedAddress.requestEventId)}</code>) both read ${esc(u.sameObservedAddress.normalised)} <span data-safe-style="color:var(--text-muted)">a shared address may be NAT / VPN / VDI</span>`
      : "—";
    return `<tr><td><code>${esc(u.eventId)}</code></td><td>${esc(String(u.at).slice(0, 19))}</td><td>${esc(u.host)}</td><td>${esc(u.kind)}${u.logonType !== undefined ? ` (type ${esc(String(u.logonType))})` : ""}</td><td>${esc(u.account)}${u.sid ? ` <span data-safe-style="color:var(--text-muted);font-size:11px">[${esc(u.sid)}]</span>` : ""}${u.realmState === "not-established" ? " <span data-safe-style='color:var(--text-muted)'>(candidate: realm not established)</span>" : ""}${u.initiator ? ` <span data-safe-style='color:var(--text-muted)'>by ${esc(u.initiator)}</span>` : ""}</td><td>${esc(u.placement)}</td><td>${esc(u.hostBaseline)}</td><td>${u.firstSeenHost ? "yes" : "no"}</td><td>${same}</td><td>${esc(u.detail || "")}</td></tr>`;
  }

  function renderKerberoastChain() {
    const el = document.getElementById("kerberoastChainPanel");
    if (!el) return;
    if (status === "loading") {
      el.innerHTML = `<div data-safe-style='color:var(--text-muted);font-size:12px'>Loading…</div>`;
      return;
    }
    if (status === "error") {
      el.innerHTML = `<div data-safe-style='color:var(--danger, #b00);font-size:12px'>The Kerberoast chain could not be loaded (${esc(chain.error || "request failed")}). Nothing here says the case holds no ticket requests.</div>`;
      return;
    }
    const leads = chain.toolLeads.map((t) => `<li><code>${esc(t.eventId)}</code> at ${esc(String(t.at).slice(0, 19))} on ${esc(t.host)}${t.account ? ` by ${esc(t.account)}` : ""}${t.detail ? ` — ${esc(t.detail)}` : ""}</li>`).join("");
    const gaps = chain.gaps.map((g) => `<li>${esc(g)}</li>`).join("");
    const excluded = Object.entries(chain.excluded || {}).map(([k, v]) => `${esc(k)} (${esc(String(v))})`).join("; ");
    const tail = `${leads ? `<div data-safe-style="margin-top:6px;font-size:12px">Roasting-tool rows not attached to a request (leads — tool presence alone does not establish that an attack ran):<ul>${leads}</ul>${chain.toolLeadsTotal > chain.toolLeads.length ? `+${esc(String(chain.toolLeadsTotal - chain.toolLeads.length))} more not shown` : ""}</div>` : ""}${gaps ? `<ul data-safe-style="font-size:12px;color:var(--text-muted)">${gaps}</ul>` : ""}${excluded ? `<div data-safe-style="font-size:11px;color:var(--text-muted)">Ticket requests not joined: ${excluded}.</div>` : ""}`;
    if (!chain.accounts.length) {
      el.innerHTML = `<div data-safe-style='color:var(--text-muted);font-size:12px'>No RC4-encrypted service-ticket request (4769) names a service account in this case. Import the domain controllers' Security logs to start from.</div>${tail}`;
      return;
    }
    const blocks = chain.accounts.map((a) => {
      const baseline = a.baseline.hostsBefore.length ? a.baseline.hostsBefore.map((h) => `${esc(h.host)} (${esc(String(h.count))}, ${esc(String(h.first).slice(0, 19))} → ${esc(String(h.last).slice(0, 19))})`).join(", ") : esc(a.baseline.note);
      const requests = a.requests.map((r) => `<tr><td><code>${esc(r.eventId)}</code></td><td>${esc(String(r.at).slice(0, 19))}</td><td>${esc(r.dc)}</td><td>${esc(r.requester || "—")}</td><td>${esc(r.clientAddress || "—")}</td><td>${esc(r.encType || "—")}${r.rc4 ? " (RC4)" : ""}</td><td>${esc(r.outcome)}</td></tr>`).join("");
      const uses = [...a.uses, ...a.candidates].map(useRow).join("");
      const more = a.usesTotal - a.uses.length + a.candidatesTotal - a.candidates.length;
      const stageColor = a.stage === "first-seen-host-use" ? "var(--danger, #b00)" : a.stage === "account-used-after" ? "var(--warning, #b60)" : "var(--text-muted)";
      return `<details open data-safe-style="margin-bottom:8px;border:1px solid var(--border);border-radius:6px;padding:4px 8px">
        <summary data-safe-style="cursor:pointer"><b>${esc(a.service)}</b> <span data-safe-style="color:var(--text-muted);font-size:12px">realm ${a.realm ? esc(a.realm) : "not established"}${a.sids.length ? `; SID ${a.sids.map(esc).join(", ")}` : ""}</span>${a.identityConflict ? ` <span data-safe-style="color:var(--danger, #b00)">identity conflict</span>` : ""} — <span data-safe-style="color:${stageColor}">${esc(a.stage)}</span> <span data-safe-style="color:var(--text-muted);font-size:12px">${esc(a.stageReason)}</span></summary>
        <div data-safe-style="padding:6px 0;font-size:12px">
          <div>${esc(String(a.requestsTotal))} request(s): ${esc(String(a.rc4Count))} RC4 issued, ${esc(String(a.aesCount))} other, ${esc(String(a.refusedCount))} refused${a.read.ticketRowsUnread ? `; ${esc(String(a.read.ticketRowsUnread))} not read` : ""}. ${esc(a.rc4Words)}.</div>
          ${a.identityConflict ? `<div data-safe-style="margin-top:2px;color:var(--danger, #b00)">Identity conflict: ${esc(a.identityConflict)}.</div>` : ""}
          <div data-safe-style="margin-top:2px">Earliest issued RC4 request: ${a.t0 ? esc(String(a.t0).slice(0, 19)) : "—"}${a.t0Anchors ? "" : " <span data-safe-style='color:var(--text-muted)'>(anchors no before / after split)</span>"}. Baseline before it: ${baseline}${a.baseline.hostsBeforeTotal > a.baseline.hostsBefore.length ? ` (+${esc(String(a.baseline.hostsBeforeTotal - a.baseline.hostsBefore.length))} host(s) not shown)` : ""}.</div>
          <div data-safe-style="margin-top:2px;color:var(--text-muted)">Acquisition: ${esc(a.acquisition)}.</div>
          <table data-safe-style="margin-top:4px"><thead><tr><th>Request</th><th>Time</th><th>Observed by (DC)</th><th>Requester</th><th>Client address</th><th>Encryption</th><th>Outcome</th></tr></thead><tbody>${requests}${a.requestsTotal > a.requests.length ? `<tr><td colspan="7">+${esc(String(a.requestsTotal - a.requests.length))} more request(s) not shown</td></tr>` : ""}</tbody></table>
          ${uses ? `<table data-safe-style="margin-top:4px"><thead><tr><th>Row</th><th>Time</th><th>Host</th><th>Kind</th><th>Account</th><th>Placement</th><th>Host baseline</th><th>First seen on host</th><th>Same observed address</th><th>Detail</th></tr></thead><tbody>${uses}${more > 0 ? `<tr><td colspan="10">+${esc(String(more))} more not shown</td></tr>` : ""}</tbody></table>` : `<div data-safe-style="color:var(--text-muted);margin-top:4px">No row where this account acts after the request${a.failedLogonsAfter ? ` (${esc(String(a.failedLogonsAfter))} failed logon(s) after it — attempts, not use)` : ""}.</div>`}
          ${a.hostsWithoutBaseline.length ? `<div data-safe-style="margin-top:4px;color:var(--text-muted)">Baseline unavailable for ${a.hostsWithoutBaseline.map(esc).join(", ")}: no rows on that host before the request, so "first seen" cannot be said there.</div>` : ""}
          ${a.toolEvidence.length ? `<div data-safe-style="margin-top:4px">Roasting-tool rows by this account's requester: ${a.toolEvidence.map((id) => `<code>${esc(id)}</code>`).join(" ")}${a.toolEvidenceTotal > a.toolEvidence.length ? ` +${esc(String(a.toolEvidenceTotal - a.toolEvidence.length))}` : ""}</div>` : ""}
          ${a.read.useRowsUnread || a.read.undated ? `<div data-safe-style="margin-top:4px;color:var(--text-muted)">Unread: ${esc(String(a.read.useRowsUnread))} use row(s) past the bound, ${esc(String(a.read.undated))} undated.</div>` : ""}
          <div data-safe-style="font-size:11px;color:var(--text-muted);margin-top:4px">A ticket request names the account; a use is the exact account acting; cracking is not observable; later use does not prove it; a shared address is not the same endpoint; a tool row is not an attack.</div>
        </div>
      </details>`;
    });
    el.innerHTML = blocks.join("") + (chain.accountsNotShown ? `<div data-safe-style="font-size:11px;color:var(--text-muted)">${esc(String(chain.accountsNotShown))} further account(s) not shown (bound).</div>` : "") + tail;
  }

  function loadKerberoastChain(caseId) {
    currentCaseId = caseId;
    chain = { accounts: [], toolLeads: [], gaps: [], excluded: {}, generated: "" };
    status = "loading";
    renderKerberoastChain();
    const gen = ++loadGen;
    // A late answer for a case the user has left, or an older load, never overwrites the panel.
    fetch(`/cases/${encodeURIComponent(caseId)}/kerberoast-chain`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        chain = d && Array.isArray(d.accounts) ? d : { accounts: [], toolLeads: [], gaps: [], excluded: {}, generated: "" };
        status = "loaded";
        renderKerberoastChain();
      })
      .catch((err) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        chain = { accounts: [], toolLeads: [], gaps: [], excluded: {}, generated: "", error: String((err && err.message) || err) };
        status = "error";
        renderKerberoastChain();
      });
  }

  window.loadKerberoastChain = loadKerberoastChain;
})();
