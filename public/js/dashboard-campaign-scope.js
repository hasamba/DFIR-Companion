// Campaign scope (#930 item 2).
//
// Per imported message: who was ADDRESSED, which mailbox a header INDICATES it reached (never
// "delivered"), and — per host — what the host's own rows establish about the attachment's own
// digest on two axes: execution (a process start) and control (each Defender disposition, in time
// order), plus whether the file was present at all. A host is attributed to a recipient only by
// the account its rows name; otherwise "recipient not established". A name-only match is a lead,
// not an outcome. Hunt leads are text; nothing here runs, contacts or sends anything.
//
// An IIFE for the same reason as js/dashboard-custody.js: this feature owns state.
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  let scope = { messages: [], messagesNotRead: 0, generated: "" };
  let currentCaseId = "";
  let loadGen = 0;
  let status = "loading"; // "loading" | "loaded" | "error": a failed request is never an empty case

  function renderCampaignScope() {
    const el = document.getElementById("campaignScopePanel");
    if (!el) return;
    if (status === "loading") {
      el.innerHTML = `<div data-safe-style='color:var(--text-muted);font-size:12px'>Loading…</div>`;
      return;
    }
    if (status === "error") {
      el.innerHTML = `<div data-safe-style='color:var(--danger, #b00);font-size:12px'>The campaign scope could not be loaded (${esc(scope.error || "request failed")}). Nothing here says the case holds no messages.</div>`;
      return;
    }
    if (!scope.messages.length) {
      el.innerHTML = `<div data-safe-style='color:var(--text-muted);font-size:12px'>No imported message with recipients or attachments. Import an .eml / .msg to start from; endpoint rows carrying the attachment's digest fill the per-host table.</div>`;
      return;
    }
    const blocks = scope.messages.map((m) => {
      const attachments = m.attachments.map((a) => `<code>${esc(a.name)}</code>${a.sha256 ? ` <span data-safe-style="color:var(--text-muted);font-size:11px">sha256 ${esc(a.sha256)}</span>` : a.md5 ? ` <span data-safe-style="color:var(--text-muted);font-size:11px">md5 ${esc(a.md5)}</span>` : a.digestUnavailable ? ` <span data-safe-style="color:var(--text-muted);font-size:11px">(digest unavailable: ${esc(a.digestUnavailable)})</span>` : ""}`).join(", ");
      const recipients = m.recipients.map((r) => `<tr><td>${esc(r.address)}</td><td>${esc(r.addressed)}</td><td>${(r.indicatedBy || []).map(esc).join(", ") || "—"}</td><td>${r.hosts.map(esc).join(", ") || "<span data-safe-style='color:var(--text-muted)'>none — no endpoint row names this account</span>"}</td></tr>`).join("");
      const hosts = m.hosts.map((h) => {
        const controls = h.controls.map((c) => `${esc(c.disposition)} at ${esc(String(c.at).slice(0, 19))}`).join("; ") || "—";
        const evidence = [...h.evidence.execution, ...h.evidence.control, ...h.evidence.present].map((id) => `<code>${esc(id)}</code>`).join(" ") + (h.evidence.more ? ` +${h.evidence.more}` : "");
        const leads = h.leads.map((l) => `<code>${esc(l.eventId)}</code> <span data-safe-style="color:var(--text-muted)">(${esc(l.kind)})</span>`).join(" ") || "—";
        const execution = h.incomplete && h.execution === "unknown" ? `incomplete (${esc(String(h.incomplete.rowsNotRead))} rows not read)` : h.execution;
        return `<tr><td>${esc(h.host)}</td><td>${h.recipient ? esc(h.recipient) : "<span data-safe-style='color:var(--text-muted)'>not established</span>"}</td><td>${esc(execution)}</td><td>${controls}</td><td>${h.present ? "yes" : h.incomplete ? "incomplete" : "no row"}</td><td>${evidence || "—"}</td><td>${leads}</td><td>${h.coverage.map(esc).join(", ") || "none"}</td></tr>`;
      }).join("");
      const leads = m.huntLeads.slice(0, 20).map((l) => `<li>${esc(l)}</li>`).join("");
      return `<details open data-safe-style="margin-bottom:8px;border:1px solid var(--border);border-radius:6px;padding:4px 8px">
        <summary data-safe-style="cursor:pointer"><b>${esc(m.subject || "(no subject)")}</b> <span data-safe-style="color:var(--text-muted);font-size:12px">— from ${esc(m.sender || "(unknown)")}, ${esc(String(m.date || "(undated)").slice(0, 19))}; Message-ID ${esc(m.messageId || "(none)")}${m.sharedWith.length ? `; ${esc(String(m.sharedWith.length + (m.sharedWithNotRead || 0)))} other message(s) carry one of these attachments` : ""}${m.attachmentsNotRead ? `; ${esc(String(m.attachmentsNotRead))} attachment part(s) past the bound, not read` : ""}</span></summary>
        <div data-safe-style="padding:6px 0;font-size:12px">
          <div>Attachments: ${attachments || "none"}</div>
          <table data-safe-style="margin-top:4px"><thead><tr><th>Recipient</th><th>Addressed</th><th>Delivery indicated by</th><th>Hosts attributed</th></tr></thead><tbody>${recipients}${m.recipientsNotRead ? `<tr><td colspan="4">+${esc(String(m.recipientsNotRead))} recipient(s) not read</td></tr>` : ""}</tbody></table>
          ${hosts ? `<table data-safe-style="margin-top:4px"><thead><tr><th>Host</th><th>Recipient</th><th>Execution</th><th>Control (in time order)</th><th>Present</th><th>Evidence</th><th>Leads</th><th>Coverage</th></tr></thead><tbody>${hosts}${m.hostsNotRead ? `<tr><td colspan="8">+${esc(String(m.hostsNotRead))} host entr(ies) not shown</td></tr>` : ""}${m.hostsUnread ? `<tr><td colspan="8">${esc(String(m.hostsUnread))} host(s) whose digest rows were all past the read bound — not absent, not read</td></tr>` : ""}</tbody></table>` : `<div data-safe-style="color:var(--text-muted);margin-top:4px">No host carries a row with an attachment's digest.</div>`}
          ${leads ? `<div data-safe-style="margin-top:4px">Hunt leads (text to run; nothing is run for you):<ul>${leads}</ul></div>` : ""}
          <div data-safe-style="font-size:11px;color:var(--text-muted);margin-top:4px">A recipient address establishes only that it was addressed; a header only indicates delivery; delivery does not establish execution; a filename is not identity; a host is attributed only by the account its rows name.</div>
        </div>
      </details>`;
    });
    el.innerHTML = blocks.join("") + (scope.messagesNotRead ? `<div data-safe-style="font-size:11px;color:var(--text-muted)">${esc(String(scope.messagesNotRead))} further message(s) not read (bound).</div>` : "");
  }

  function loadCampaignScope(caseId) {
    currentCaseId = caseId;
    scope = { messages: [], messagesNotRead: 0, generated: "" };
    status = "loading";
    renderCampaignScope();
    const gen = ++loadGen;
    // A late answer for a case the user has left, or an older load, never overwrites the panel.
    fetch(`/cases/${encodeURIComponent(caseId)}/campaign-scope`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        scope = d && Array.isArray(d.messages) ? d : { messages: [], messagesNotRead: 0, generated: "" };
        status = "loaded";
        renderCampaignScope();
      })
      .catch((err) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        scope = { messages: [], messagesNotRead: 0, generated: "", error: String((err && err.message) || err) };
        status = "error";
        renderCampaignScope();
      });
  }

  window.loadCampaignScope = loadCampaignScope;
})();
