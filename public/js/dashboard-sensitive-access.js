// Sensitive access (#930 item 7).
//
// The analyst declares SENSITIVE LOCATIONS — an exact file or a folder on one host or any host —
// because sensitivity is a classification the case does not hold, and a filename is never a rule.
// The reading then says, per object under a location: access recorded (a 4663), data read (a read
// right on an object evidenced as a FILE at that time — `0x1` alone is read OR listing), read by
// a candidate instance (one process start with that pid and image on the host before the access),
// corroborated suspicious read (that candidate's own process row or its session's logon graded
// High or above). Later archive activity and later connections by the same process GUID are
// subsequent activity by that process — never "staged", never "transferred". A handle request is
// not an access. Nothing is fetched; no host is contacted.
//
// An IIFE for the same reason as js/dashboard-custody.js: this feature owns state.
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  let reading = { locations: [], collections: [], hosts: [], generated: "" };
  let currentCaseId = "";
  let loadGen = 0;
  let status = "loading"; // "loading" | "loaded" | "error"
  let mutationError = ""; // a failed declare / delete, shown beside the last loaded reading

  function api(path, init) {
    return fetch(`/cases/${encodeURIComponent(currentCaseId)}${path}`, init).then((r) =>
      r.json().then((body) => ({ ok: r.ok, status: r.status, body })),
    );
  }

  const stageColor = (s) =>
    s === "corroborated-suspicious-read" ? "var(--danger, #b00)" : s === "read-by-candidate-instance" ? "var(--warning, #b60)" : "var(--text-muted)";

  function accessRow(a) {
    const inst = `${esc(a.instance.state)}${a.instance.startEventId ? ` (<code>${esc(a.instance.startEventId)}</code>)` : ""}<br><span data-safe-style="color:var(--text-muted)">${esc(a.instance.reason)}</span>`;
    const sess = `${esc(a.session.state)}${a.session.logonEventId ? ` (<code>${esc(a.session.logonEventId)}</code>${a.session.logonType !== undefined ? `, type ${esc(String(a.session.logonType))}` : ""}${a.session.sourceAddress ? `, from ${esc(a.session.sourceAddress)}` : ""})` : ""}<br><span data-safe-style="color:var(--text-muted)">${esc(a.session.reason)}</span>`;
    const ids = (l) => (l && l.length ? l.map((id) => `<code>${esc(id)}</code>`).join(" ") : "—");
    return `<tr><td><code>${esc(a.eventId)}</code></td><td>${esc(String(a.at).slice(0, 19))}</td><td>${esc(a.kind)}</td><td>${esc(a.rights.join(", ") || "—")}${a.mask ? ` <span data-safe-style="color:var(--text-muted)">(${esc(a.mask)})</span>` : ""}${a.objectType && a.objectType !== "File" ? ` <span data-safe-style="color:var(--text-muted)">${esc(a.objectType)} object</span>` : ""}</td><td>${a.dataRead ? "<b>yes</b>" : "no"}<br><span data-safe-style="color:var(--text-muted)">${esc(a.fileEvidence)}</span></td><td>${esc(a.account || "")}${a.sid ? ` <span data-safe-style="color:var(--text-muted);font-size:11px">[${esc(a.sid)}]</span>` : ""}</td><td>${esc(a.image || "")}${a.pid !== undefined ? ` (${esc(String(a.pid))})` : ""}</td><td>${inst}</td><td>${sess}</td><td>${a.corroboration.length ? a.corroboration.map(esc).join("; ") : "—"}</td><td>${ids(a.pivots.archiveCreates)}</td><td>${ids(a.pivots.connections)}</td><td>${ids(a.deletionCandidates)}</td></tr>`;
  }

  function renderLocation(l) {
    const loc = l.location;
    const objects = l.objects.map((o) => {
      const rows = o.accesses.map(accessRow).join("");
      return `<details data-safe-style="margin:4px 0"><summary data-safe-style="cursor:pointer"><code>${esc(o.path)}</code> on ${esc(o.host)} — <span data-safe-style="color:${stageColor(o.stage)}">${esc(o.stage)}</span> <span data-safe-style="color:var(--text-muted);font-size:12px">${esc(o.stageReason)} — ${esc(String(o.accessesTotal))} row(s) analysed, ${esc(String(o.evidenceTotals["data-read"]))} data read(s), ${esc(String(o.evidenceTotals["corroborated-suspicious-read"]))} corroborated</span></summary>
        <table data-safe-style="margin-top:4px;font-size:11px"><thead><tr><th>Row</th><th>Time</th><th>Kind</th><th>Rights</th><th>Data read</th><th>Account</th><th>Process (pid)</th><th>Instance</th><th>Session</th><th>Corroboration</th><th>Later archive create</th><th>Later connection</th><th>Deletion candidate</th></tr></thead><tbody>${rows}${o.accessesTotal > o.accesses.length ? `<tr><td colspan="13">+${esc(String(o.accessesTotal - o.accesses.length))} more not shown</td></tr>` : ""}</tbody></table></details>`;
    });
    const unread = l.hostsRead.filter((h) => h.accessRowsUnread || h.contextRowsUnread).map((h) => `${esc(h.host)}: ${esc(String(h.accessRowsUnread))} object-access row(s) and ${esc(String(h.contextRowsUnread))} handle-request / share-check row(s) past the read bound, not read`).join("; ");
    return `<details open data-safe-style="margin-bottom:8px;border:1px solid var(--border);border-radius:6px;padding:4px 8px">
      <summary data-safe-style="cursor:pointer"><b>${esc(loc.path)}</b> <span data-safe-style="color:var(--text-muted);font-size:12px">${esc(loc.kind)}, ${loc.host ? esc(loc.host) : "any host"}${loc.note ? ` — ${esc(loc.note)}` : ""}</span> <button type="button" data-sn-delete="${esc(loc.id)}" data-safe-style="font-size:11px;margin-left:8px">delete</button></summary>
      <div data-safe-style="padding:6px 0;font-size:12px">
        <div data-safe-style="color:var(--text-muted)">${esc(l.note)}.</div>
        ${objects.join("")}${l.objectsTotal > l.objects.length ? `<div data-safe-style="color:var(--text-muted)">+${esc(String(l.objectsTotal - l.objects.length))} object(s) not shown</div>` : ""}
        ${unread ? `<div data-safe-style="color:var(--text-muted);margin-top:4px">${unread}.</div>` : ""}
      </div>
    </details>`;
  }

  function renderSensitiveAccess() {
    const el = document.getElementById("sensitiveAccessPanel");
    if (!el) return;
    const form = `<form id="sensitiveLocationDeclare" data-safe-style="display:flex;gap:6px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px">
      <label data-safe-style="font-size:12px">Host (blank = any)<br><input name="host" placeholder="FS01" data-safe-style="width:120px"></label>
      <label data-safe-style="font-size:12px">Path<br><input name="path" required placeholder="C:\\Finance\\Board\\minutes.docx" data-safe-style="width:300px"></label>
      <label data-safe-style="font-size:12px">Kind<br><select name="kind"><option value="file">file</option><option value="folder">folder</option></select></label>
      <label data-safe-style="font-size:12px">Note<br><input name="note" placeholder="why it matters" data-safe-style="width:200px"></label>
      <button type="submit">Declare sensitive location</button>
    </form>`;
    const mutation = mutationError ? `<div data-safe-style='color:var(--danger, #b00);font-size:12px;margin-bottom:6px'>${esc(mutationError)} — the declared locations may differ from what is shown; reload to check.</div>` : "";
    if (status === "loading") el.innerHTML = form + mutation + `<div data-safe-style='color:var(--text-muted);font-size:12px'>Loading…</div>`;
    else if (status === "error") el.innerHTML = form + mutation + `<div data-safe-style='color:var(--danger, #b00);font-size:12px'>The sensitive access reading could not be loaded (${esc(reading.error || "request failed")}). Nothing here says the case holds no access rows.</div>`;
    else if (!reading.locations.length) el.innerHTML = form + mutation + `<div data-safe-style='color:var(--text-muted);font-size:12px'>No sensitive location declared — an object-access row is not a sensitive read without one. Declare the file or folder that matters; a filename is never a rule.</div>` + renderHosts();
    else el.innerHTML = form + mutation + reading.locations.map(renderLocation).join("") + renderCollections() + renderHosts();
    const f = el.querySelector("#sensitiveLocationDeclare");
    if (f) f.addEventListener("submit", onDeclare);
    el.querySelectorAll("button[data-sn-delete]").forEach((b) => b.addEventListener("click", () => deleteLocation(b.getAttribute("data-sn-delete"))));
  }

  function renderCollections() {
    if (!reading.collections.length) return "";
    const rows = reading.collections.map((c) => `<tr><td>${esc(c.host)}</td><td><code>${esc(c.instance)}</code></td><td>${esc(c.image || "")}</td><td>${esc(String(c.objects))}</td><td>${esc(String(c.from).slice(0, 19))} → ${esc(String(c.to).slice(0, 19))}</td><td>${esc(c.state)}</td><td>${esc(c.note)}</td></tr>`).join("");
    return `<div data-safe-style="margin-top:8px;font-size:12px"><b>Collection shapes</b> — one candidate instance reading many evidenced files in a window; an indexer, a backup, an AV scan or a collection: the record does not say which.<table data-safe-style="margin-top:4px"><thead><tr><th>Host</th><th>Instance</th><th>Image</th><th>Objects</th><th>Window</th><th>State</th><th>Note</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderHosts() {
    if (!reading.hosts.length) return "";
    const rows = reading.hosts.map((h) => `<tr><td>${esc(h.host)}</td><td>${esc(String(h.accessRows))}${h.accessRowsUnread ? ` (+${esc(String(h.accessRowsUnread))} unread)` : ""}</td><td>${esc(String(h.contextRows))}${h.contextRowsUnread ? ` (+${esc(String(h.contextRowsUnread))} unread)` : ""}</td><td>${h.span ? `${esc(String(h.span[0]).slice(0, 19))} → ${esc(String(h.span[1]).slice(0, 19))}` : "—"}</td><td>${esc(String(h.processStarts))}</td><td>${esc(String(h.logons))}</td><td>${esc(String(h.findings))}</td><td>${esc(h.note)}</td></tr>`).join("");
    return `<div data-safe-style="margin-top:8px;font-size:12px"><b>Hosts</b> — context only: object-access rows elsewhere on a host are not coverage of a location; a host's findings never make a read suspicious.<table data-safe-style="margin-top:4px"><thead><tr><th>Host</th><th>Object-access rows</th><th>Handle-request / share-check rows</th><th>Span</th><th>Process starts</th><th>Logons</th><th>Rows in findings</th><th>Note</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function onDeclare(ev) {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const body = { host: String(fd.get("host") || ""), path: String(fd.get("path") || ""), kind: String(fd.get("kind") || "file"), note: String(fd.get("note") || "") };
    const caseId = currentCaseId;
    api("/sensitive-locations", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then((r) => {
        if (currentCaseId !== caseId) return;
        if (!r.ok) {
          mutationError = `Could not declare the sensitive location: ${r.body && r.body.error ? r.body.error : `HTTP ${r.status}`}`;
          renderSensitiveAccess();
          return;
        }
        mutationError = "";
        loadSensitiveAccess(caseId);
      })
      .catch((err) => {
        if (currentCaseId !== caseId) return;
        mutationError = `Could not declare the sensitive location: ${String((err && err.message) || err)}`;
        renderSensitiveAccess();
      });
  }

  function deleteLocation(id) {
    if (!window.confirm("Delete this sensitive location?")) return;
    const caseId = currentCaseId;
    fetch(`/cases/${encodeURIComponent(caseId)}/sensitive-locations/${encodeURIComponent(id)}`, { method: "DELETE" })
      .then((r) => {
        if (currentCaseId !== caseId) return;
        if (!r.ok) {
          mutationError = `Could not delete the sensitive location (HTTP ${r.status})`;
          renderSensitiveAccess();
          return;
        }
        mutationError = "";
        loadSensitiveAccess(caseId);
      })
      .catch((err) => {
        if (currentCaseId !== caseId) return;
        mutationError = `Could not delete the sensitive location: ${String((err && err.message) || err)}`;
        renderSensitiveAccess();
      });
  }

  function loadSensitiveAccess(caseId) {
    currentCaseId = caseId;
    reading = { locations: [], collections: [], hosts: [], generated: "" };
    status = "loading";
    renderSensitiveAccess();
    const gen = ++loadGen;
    fetch(`/cases/${encodeURIComponent(caseId)}/sensitive-access`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        reading = d && Array.isArray(d.locations) ? d : { locations: [], collections: [], hosts: [], generated: "" };
        status = "loaded";
        renderSensitiveAccess();
      })
      .catch((err) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        reading = { locations: [], collections: [], hosts: [], generated: "", error: String((err && err.message) || err) };
        status = "error";
        renderSensitiveAccess();
      });
  }

  window.loadSensitiveAccess = loadSensitiveAccess;
})();
