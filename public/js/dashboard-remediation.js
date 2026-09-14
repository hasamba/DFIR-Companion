// Remediation checks (#930 item 9 — #969).
//
// The analyst declares a REMEDIATION BOUNDARY (host, artifact, when, how long to watch), runs a
// VERIFY that returns FACTS — which rows on that host named the artifact inside the window and
// what each one IS, how much telemetry of each family the case held — and records the residual-
// risk STATUS against the receipt of the facts they read. The panel never says "clean": the
// sentence under every check is "The check lists what was seen and what was covered. Only you
// can say the foothold is gone." A `checked — not observed` against a truncated, still-open or
// under-covered check needs the analyst's own override note.
//
// An IIFE for the same reason as js/dashboard-custody.js: this feature owns state.
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  let boundaries = [];
  let facts = {}; // boundary id → the last verify result this session (never persisted here)
  let currentCaseId = "";
  // Request generations: a load or a verify that resolves after a newer one is dropped, so an
  // older answer for the SAME case never replaces newer boundaries or facts.
  let loadGen = 0;
  const verifyGen = {}; // boundary id → generation of the latest verify request

  const KINDS = ["path", "hash", "account", "domain", "ip", "service", "task", "regkey"];
  const STATUSES = ["unreviewed", "recurrence-observed", "checked-not-observed", "insufficient-coverage"];

  function api(path, init) {
    return fetch(`/cases/${encodeURIComponent(currentCaseId)}/remediation${path}`, init).then((r) =>
      r.json().then((body) => ({ ok: r.ok, status: r.status, body })),
    );
  }

  function renderRemediation() {
    const el = document.getElementById("remediationPanel");
    if (!el) return;
    const form = `<form id="remediationDeclare" data-safe-style="display:flex;gap:6px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px">
      <label data-safe-style="font-size:12px">Host<br><input name="host" required placeholder="WS-042" data-safe-style="width:140px"></label>
      <label data-safe-style="font-size:12px">Kind<br><select name="kind">${KINDS.map((k) => `<option value="${k}">${k}</option>`).join("")}</select></label>
      <label data-safe-style="font-size:12px">Artifact<br><input name="value" required placeholder="C:\\Users\\x\\evil.exe" data-safe-style="width:260px"></label>
      <label data-safe-style="font-size:12px">Remediated at (UTC)<br><input name="remediatedAt" type="datetime-local" required></label>
      <label data-safe-style="font-size:12px">Window (h)<br><input name="windowHours" type="number" min="1" max="720" value="168" data-safe-style="width:70px"></label>
      <label data-safe-style="font-size:12px">Note<br><input name="note" placeholder="what was done" data-safe-style="width:200px"></label>
      <button type="submit">Declare boundary</button>
    </form>`;
    const list = boundaries.length
      ? boundaries.map(renderBoundary).join("")
      : `<div data-safe-style='color:var(--text-muted);font-size:12px'>No remediation boundary declared. Declare one to check whether the same foothold shows up again — the check reports what it saw and how much it covered; the status is yours.</div>`;
    el.innerHTML = form + list;
    const f = el.querySelector("#remediationDeclare");
    if (f) f.addEventListener("submit", onDeclare);
    el.querySelectorAll("button[data-rem-verify]").forEach((b) => b.addEventListener("click", () => verifyBoundary(b.getAttribute("data-rem-verify"))));
    el.querySelectorAll("button[data-rem-delete]").forEach((b) => b.addEventListener("click", () => deleteBoundary(b.getAttribute("data-rem-delete"))));
    el.querySelectorAll("button[data-rem-attach]").forEach((b) => b.addEventListener("click", () => attachEvidence(b.getAttribute("data-rem-attach"), b.getAttribute("data-event"))));
    el.querySelectorAll("form[data-rem-status]").forEach((sf) => sf.addEventListener("submit", onStatus));
  }

  function renderBoundary(b) {
    const fx = facts[b.id];
    const statusLine = `<span data-safe-style="font-size:12px">status: <b>${esc(b.status)}</b>${b.statusSetAt ? ` (${esc(String(b.statusSetAt).slice(0, 16))})` : ""}${b.statusNote ? ` — ${esc(b.statusNote)}` : ""}${b.statusOverrideNote ? ` — override: ${esc(b.statusOverrideNote)}` : ""}</span>`;
    const link = b.taskLink === "linked" ? " · linked to a playbook task" : b.taskLink === "text-changed" ? " · playbook task text changed since" : b.taskLink === "orphaned" ? " · the playbook task it named is gone" : "";
    const receipts = (b.receipts || []).slice(-5).reverse().map((r) =>
      `<div data-safe-style="font-size:11px;color:var(--text-muted)">check ${esc(r.id)} at ${esc(String(r.at).slice(0, 19))}: ${esc(String(r.hitTotal))} row(s) named it${r.stale ? " — recorded against older data" : ""}${r.truncated ? " — truncated" : ""}${r.window && r.window.open ? " — window open" : ""}${r.coverageGapped ? " — a relevant family not covered" : ""}${b.statusReceiptId === r.id ? " — <b>the status names this check</b>" : ""}</div>`,
    ).join("");
    const receiptOptions = (b.receipts || []).slice().reverse().map((r) => `<option value="${esc(r.id)}"${b.statusReceiptId === r.id ? " selected" : ""}>${esc(r.id)} (${esc(String(r.at).slice(0, 16))})</option>`).join("");
    const statusForm = `<form data-rem-status="${esc(b.id)}" data-safe-style="display:flex;gap:6px;flex-wrap:wrap;align-items:flex-end;margin-top:6px">
      <label data-safe-style="font-size:12px">Status<br><select name="status">${STATUSES.map((s) => `<option value="${s}"${b.status === s ? " selected" : ""}>${s}</option>`).join("")}</select></label>
      <label data-safe-style="font-size:12px">Against check<br><select name="receiptId"><option value="">—</option>${receiptOptions}</select></label>
      <label data-safe-style="font-size:12px">Note<br><input name="note" value="${esc(b.statusNote || "")}" data-safe-style="width:220px"></label>
      <label data-safe-style="font-size:12px">Override note (when the check is truncated, open or under-covered)<br><input name="override" value="${esc(b.statusOverrideNote || "")}" data-safe-style="width:260px"></label>
      <button type="submit">Record status</button>
    </form>
    <div data-safe-style="font-size:11px;color:var(--text-muted);margin-top:4px">The check lists what was seen and what was covered. Only you can say the foothold is gone.</div>`;
    return `<details open data-safe-style="margin-bottom:8px;border:1px solid var(--border);border-radius:6px;padding:4px 8px">
      <summary data-safe-style="cursor:pointer"><b>${esc(b.artifact.kind)}</b> <code>${esc(b.artifact.value)}</code> on <b>${esc(b.host)}</b> <span data-safe-style="color:var(--text-muted);font-size:12px">— remediated ${esc(String(b.remediatedAt).slice(0, 16))}, watch ${esc(String(b.windowHours))} h${link}</span></summary>
      <div data-safe-style="padding:6px 0">
        ${b.note ? `<div data-safe-style="font-size:12px;margin-bottom:4px">${esc(b.note)}</div>` : ""}
        <div data-safe-style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <button type="button" data-rem-verify="${esc(b.id)}" title="Read the case for rows on this host naming the artifact inside the window; returns facts and writes a receipt">Verify now</button>
          <button type="button" data-rem-delete="${esc(b.id)}" title="Remove this boundary and its receipts">Delete</button>
          ${statusLine}
        </div>
        ${fx ? renderFacts(b, fx) : ""}
        ${receipts}
        ${statusForm}
        ${b.evidence && b.evidence.length ? `<div data-safe-style="font-size:11px;color:var(--text-muted);margin-top:4px">attached evidence: ${b.evidence.map((id) => `<code>${esc(id)}</code>`).join(" ")}</div>` : ""}
      </div>
    </details>`;
  }

  function renderFacts(b, fx) {
    const fam = (fx.families || []).map((f) => `<tr><td>${esc(f.family)}</td><td>${f.relevant ? "yes" : ""}</td><td>${esc(String(f.rowsInWindow))}</td><td>${esc(f.state)}</td></tr>`).join("");
    const cov = (fx.coverage || []).slice(0, 20).map((c) => `<tr><td>${esc(c.store)}</td><td>${esc(c.source)}</td><td>${esc(String(c.rows))}</td><td>${esc(String(c.earliest).slice(0, 19))}</td><td>${esc(String(c.latest).slice(0, 19))}</td></tr>`).join("");
    const hits = (fx.hits || []).map((h) =>
      `<tr><td>${esc(String(h.timestamp).slice(0, 19))}</td><td>${esc(h.cls)}${h.classNote ? ` <span data-safe-style="color:var(--text-muted)">(${esc(h.classNote)})</span>` : ""}</td><td>${esc(h.strength)} on ${esc(h.matchedOn)}</td><td>${esc(h.source)}</td><td>${esc(h.description)}${h.changesSideWhenAligned ? " <b>(before the boundary once clock-aligned)</b>" : ""}</td><td>${(b.evidence || []).includes(h.id) ? "attached" : `<button type="button" data-rem-attach="${esc(b.id)}" data-event="${esc(h.id)}" title="${h.store === "super" ? "Promote this super-timeline row into the case and attach it as evidence" : "Attach this row as evidence"}">Attach</button>`}</td></tr>`,
    ).join("");
    const notes = [
      fx.truncated ? `read truncated: ${esc(fx.truncatedBy || "")}` : "",
      fx.window && fx.window.open ? "the window is still open" : "",
      fx.inconsistent ? "the stores changed while the read ran" : "",
      fx.retentionNote ? esc(fx.retentionNote) : "",
      fx.undated ? `${esc(String(fx.undated))} undated row(s) skipped` : "",
      fx.clock && fx.clock.alignment === "on" ? `clock alignment on${fx.clock.boundaryAligned ? `; boundary in the corrected domain: ${esc(fx.clock.boundaryAligned)}` : ""}` : "times compared as recorded",
      esc(fx.lateImportNote || ""),
    ].filter(Boolean).map((n) => `<div data-safe-style="font-size:11px;color:var(--text-muted)">${n}</div>`).join("");
    return `<div data-safe-style="margin-top:6px;font-size:12px">
      <div>Host spellings read: ${(fx.spellings || []).map((s) => `<code>${esc(s)}</code>`).join(" ") || "<i>none held by the case</i>"} · window ${esc(String(fx.window.from).slice(0, 19))} → ${esc(String(fx.window.to).slice(0, 19))} · ${esc(String(fx.hitTotal))} row(s) named the artifact · receipt <code>${esc(fx.receipt.id)}</code></div>
      ${notes}
      <table data-safe-style="margin-top:4px"><thead><tr><th>Family</th><th>Relevant</th><th>Rows in window</th><th>Coverage</th></tr></thead><tbody>${fam}</tbody></table>
      ${cov ? `<details><summary data-safe-style="cursor:pointer;font-size:11px">Per-source coverage</summary><table><thead><tr><th>Store</th><th>Source</th><th>Rows</th><th>Earliest</th><th>Latest</th></tr></thead><tbody>${cov}</tbody></table></details>` : ""}
      ${hits ? `<table data-safe-style="margin-top:4px"><thead><tr><th>Time</th><th>What the row is</th><th>Match</th><th>Source</th><th>Row</th><th></th></tr></thead><tbody>${hits}</tbody></table>` : `<div data-safe-style="font-size:12px;margin-top:4px">No row on this host named the artifact inside the window — a coverage fact (see the families above), not evidence that the foothold is gone.</div>`}
    </div>`;
  }

  function onDeclare(ev) {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const local = String(fd.get("remediatedAt") || "");
    const body = {
      host: String(fd.get("host") || ""),
      artifact: { kind: String(fd.get("kind") || ""), value: String(fd.get("value") || "") },
      remediatedAt: local ? new Date(`${local}Z`).toISOString() : "",
      windowHours: Number(fd.get("windowHours") || 168),
      note: String(fd.get("note") || ""),
    };
    const caseId = currentCaseId;
    api("", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
      .then((r) => {
        if (currentCaseId !== caseId) return;
        if (!r.ok) {
          window.alert(`Could not declare the boundary: ${r.body && r.body.error ? r.body.error : r.status}`);
          return;
        }
        loadRemediation(caseId);
      })
      .catch(() => {});
  }

  function verifyBoundary(id) {
    const caseId = currentCaseId;
    const gen = (verifyGen[id] = (verifyGen[id] || 0) + 1);
    api(`/${encodeURIComponent(id)}/verify`, { method: "POST" })
      .then((r) => {
        if (currentCaseId !== caseId || verifyGen[id] !== gen) return;
        if (r.ok) facts[id] = r.body;
        else window.alert(`Verify failed: ${r.body && r.body.error ? r.body.error : r.status}`);
        loadRemediation(caseId, true);
      })
      .catch(() => {});
  }

  function deleteBoundary(id) {
    if (!window.confirm("Delete this boundary and its receipts?")) return;
    const caseId = currentCaseId;
    fetch(`/cases/${encodeURIComponent(caseId)}/remediation/${encodeURIComponent(id)}`, { method: "DELETE" })
      .then(() => {
        if (currentCaseId !== caseId) return;
        delete facts[id];
        loadRemediation(caseId, true);
      })
      .catch(() => {});
  }

  function attachEvidence(id, eventId) {
    const caseId = currentCaseId;
    api(`/${encodeURIComponent(id)}/attach`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ eventIds: [eventId] }),
    })
      .then((r) => {
        if (currentCaseId !== caseId) return;
        if (!r.ok) window.alert(`Could not attach: ${r.body && r.body.error ? r.body.error : r.status}`);
        loadRemediation(caseId, true);
      })
      .catch(() => {});
  }

  function onStatus(ev) {
    ev.preventDefault();
    const id = ev.target.getAttribute("data-rem-status");
    const fd = new FormData(ev.target);
    const body = {
      status: String(fd.get("status") || ""),
      receiptId: String(fd.get("receiptId") || ""),
      note: String(fd.get("note") || ""),
      override: String(fd.get("override") || ""),
    };
    const caseId = currentCaseId;
    api(`/${encodeURIComponent(id)}/status`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
      .then((r) => {
        if (currentCaseId !== caseId) return;
        if (!r.ok) window.alert(`Could not record the status: ${r.body && r.body.error ? r.body.error : r.status}`);
        loadRemediation(caseId, true);
      })
      .catch(() => {});
  }

  function loadRemediation(caseId, keepFacts) {
    if (currentCaseId !== caseId) facts = {};
    else if (!keepFacts) facts = {};
    currentCaseId = caseId;
    boundaries = [];
    renderRemediation();
    // A late answer for a case the user has left, or an older load for this case, never
    // overwrites the panel.
    const gen = ++loadGen;
    fetch(`/cases/${encodeURIComponent(caseId)}/remediation`)
      .then((r) => (r.ok ? r.json() : { boundaries: [] }))
      .then((d) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        boundaries = d && Array.isArray(d.boundaries) ? d.boundaries : [];
        renderRemediation();
      })
      .catch(() => {});
  }

  window.loadRemediation = loadRemediation;
})();
