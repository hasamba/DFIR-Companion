// Served exposure (#930 item 4).
//
// The analyst declares SERVED LOCATIONS — on web server H, URL prefix P is served from local root
// R — because virtual hosts, aliases and rewrites are server configuration the case does not
// hold, and a request path is not a file path without one. The reading then says, per resource
// under a root: suspected exposure (a file row under the root), retrieval requested (an access-log
// request mapped to it while a version covered it), response size recorded (what the server
// logged — a size, never a transfer, never client receipt), corroborated disclosure (a logged size
// while the resource was confirmed sensitive or was the sensitive document by digest). A public
// location's unconfirmed resources are negative controls; a confirmed one under it is a conflict.
// Every reason says whether the read was complete. Nothing is fetched; no server is contacted.
//
// An IIFE for the same reason as js/dashboard-custody.js: this feature owns state.
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  let exposure = { locations: [], generated: "" };
  let currentCaseId = "";
  let loadGen = 0;
  let status = "loading"; // "loading" | "loaded" | "error"

  function api(path, init) {
    return fetch(`/cases/${encodeURIComponent(currentCaseId)}${path}`, init).then((r) =>
      r.json().then((body) => ({ ok: r.ok, status: r.status, body })),
    );
  }

  function renderServedExposure() {
    const el = document.getElementById("servedExposurePanel");
    if (!el) return;
    const form = `<form id="servedLocationDeclare" data-safe-style="display:flex;gap:6px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px">
      <label data-safe-style="font-size:12px">Web server host<br><input name="host" required placeholder="WEB01" data-safe-style="width:120px"></label>
      <label data-safe-style="font-size:12px">Virtual host (optional)<br><input name="vhost" placeholder="files.example" data-safe-style="width:140px"></label>
      <label data-safe-style="font-size:12px">URL prefix<br><input name="urlPrefix" required value="/" data-safe-style="width:120px"></label>
      <label data-safe-style="font-size:12px">Local root<br><input name="localRoot" required placeholder="C:\\inetpub\\wwwroot" data-safe-style="width:220px"></label>
      <label data-safe-style="font-size:12px">Index files (comma)<br><input name="indexFiles" placeholder="index.html" data-safe-style="width:120px"></label>
      <label data-safe-style="font-size:12px">Sensitive paths (comma, below the root)<br><input name="sensitive" placeholder="backup/db.sql" data-safe-style="width:220px"></label>
      <label data-safe-style="font-size:12px">Sensitive sha256 (comma)<br><input name="sensitiveDigests" placeholder="…" data-safe-style="width:200px"></label>
      <label data-safe-style="font-size:12px"><input name="public" type="checkbox"> public / authorised download area</label>
      <button type="submit">Declare served location</button>
    </form>`;
    if (status === "loading") {
      el.innerHTML = form + `<div data-safe-style='color:var(--text-muted);font-size:12px'>Loading…</div>`;
    } else if (status === "error") {
      el.innerHTML = form + `<div data-safe-style='color:var(--danger, #b00);font-size:12px'>The served exposure could not be loaded (${esc(exposure.error || "request failed")}). Nothing here says the case holds no exposure.</div>`;
    } else if (!exposure.locations.length) {
      el.innerHTML = form + `<div data-safe-style='color:var(--text-muted);font-size:12px'>No served location declared — a request path is not a file path without one. Declare where a URL prefix is served from on the web server.</div>`;
    } else {
      el.innerHTML = form + exposure.locations.map(renderLocation).join("");
    }
    const f = el.querySelector("#servedLocationDeclare");
    if (f) f.addEventListener("submit", onDeclare);
    el.querySelectorAll("button[data-sl-delete]").forEach((b) => b.addEventListener("click", () => deleteLocation(b.getAttribute("data-sl-delete"))));
  }

  function renderLocation(e) {
    const l = e.location;
    const gaps = e.gaps.map((g) => `<div data-safe-style="font-size:11px;color:var(--text-muted)">gap: ${esc(g)}</div>`).join("");
    const rows = e.resources.map((r) => {
      const requests = r.requests.slice(0, 5).map((q) => `${esc(String(q.at).slice(0, 19))} ${esc(q.method)} → ${esc(String(q.status ?? "?"))}${q.size !== undefined ? ` (${esc(String(q.size))})` : ""} <span data-safe-style="color:var(--text-muted)">[${esc(q.placement)}; ${esc(q.sizeWords)}]</span>`).join("<br>") + (r.requestsTotal > 5 ? `<br>… ${esc(String(r.requestsTotal))} total` : "");
      const sens = `${esc(r.sensitivity)}${r.negativeControl ? " — <span data-safe-style='color:var(--text-muted)'>negative control (public)</span>" : ""}${r.conflict ? ` — <b>conflict:</b> ${esc(r.conflict)}` : ""}`;
      return `<tr><td><code>${esc(r.url)}</code></td><td><b>${esc(r.stage)}</b></td><td>${sens}</td><td>${esc(String(r.versions.length))} version(s), ${esc(String(r.observations.length))} observation(s)${r.historicalLeads.length ? `, ${esc(String(r.historicalLeads.length))} historical lead(s)` : ""}</td><td>${requests || "none"}</td><td>${esc(r.stageReason)}</td></tr>`;
    }).join("");
    const unevidenced = e.unevidencedRequests.slice(0, 20).map((u) => `<li><code>${esc(u.path)}</code>: ${esc(String(u.count))} request(s), status ${u.statuses.map(String).map(esc).join("/")}</li>`).join("");
    const unmapped = e.unmapped.count ? ` · ${esc(String(e.unmapped.count))} request(s) not mapped (${Object.entries(e.unmapped.reasons).map(([k, v]) => `${esc(k)}: ${esc(String(v))}`).join(", ")})` : "";
    return `<details open data-safe-style="margin-bottom:8px;border:1px solid var(--border);border-radius:6px;padding:4px 8px">
      <summary data-safe-style="cursor:pointer"><b>${esc(l.host)}</b>${l.vhost ? ` (${esc(l.vhost)})` : ""}: <code>${esc(l.urlPrefix || "/")}</code> ← <code>${esc(l.localRoot)}</code>${l.public ? " <span data-safe-style='color:var(--text-muted)'>— declared public</span>" : ""} <button type="button" data-sl-delete="${esc(l.id)}" data-safe-style="margin-left:8px">Delete</button></summary>
      <div data-safe-style="padding:6px 0;font-size:12px">
        <div data-safe-style="font-size:11px;color:var(--text-muted)">read ${esc(String(e.read.fileRows))} file row(s), ${esc(String(e.read.webRows))} web row(s)${e.read.fileRowsUnread + e.read.webRowsUnread ? `; ${esc(String(e.read.fileRowsUnread + e.read.webRowsUnread))} unread` : ""}${e.read.undated ? `; ${esc(String(e.read.undated))} undated` : ""}${unmapped} · coverage: ${e.coverage.map(esc).join(", ") || "none"}</div>
        ${gaps}
        ${rows ? `<table data-safe-style="margin-top:4px"><thead><tr><th>Resource</th><th>Stage</th><th>Sensitivity</th><th>Versions</th><th>Requests</th><th>Reason</th></tr></thead><tbody>${rows}${e.resourcesNotShown ? `<tr><td colspan="6">+${esc(String(e.resourcesNotShown))} resource(s) not shown</td></tr>` : ""}</tbody></table>` : `<div data-safe-style="color:var(--text-muted);margin-top:4px">No file row under this root.</div>`}
        ${unevidenced ? `<div data-safe-style="margin-top:4px">Requests to paths with no file evidence (leads, no exposure claim):<ul>${unevidenced}</ul></div>` : ""}
        <div data-safe-style="font-size:11px;color:var(--text-muted);margin-top:4px">A logged size is what the server said, not a transfer and not receipt; an extension is not sensitivity; disclosure is corroborated only for a resource you confirmed or whose covering version is the sensitive document by digest.</div>
      </div>
    </details>`;
  }

  const list = (v) => String(v || "").split(",").map((s) => s.trim()).filter(Boolean);

  function onDeclare(ev) {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const body = {
      host: String(fd.get("host") || ""),
      vhost: String(fd.get("vhost") || ""),
      urlPrefix: String(fd.get("urlPrefix") || "/"),
      localRoot: String(fd.get("localRoot") || ""),
      indexFiles: list(fd.get("indexFiles")),
      sensitive: list(fd.get("sensitive")),
      sensitiveDigests: list(fd.get("sensitiveDigests")),
      public: fd.get("public") === "on",
    };
    const caseId = currentCaseId;
    api("/served-locations", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
      .then((r) => {
        if (currentCaseId !== caseId) return;
        if (!r.ok) {
          window.alert(`Could not declare the served location: ${r.body && r.body.error ? r.body.error : r.status}`);
          return;
        }
        loadServedExposure(caseId);
      })
      .catch(() => {});
  }

  function deleteLocation(id) {
    if (!window.confirm("Delete this served location?")) return;
    const caseId = currentCaseId;
    fetch(`/cases/${encodeURIComponent(caseId)}/served-locations/${encodeURIComponent(id)}`, { method: "DELETE" })
      .then(() => {
        if (currentCaseId !== caseId) return;
        loadServedExposure(caseId);
      })
      .catch(() => {});
  }

  function loadServedExposure(caseId) {
    currentCaseId = caseId;
    exposure = { locations: [], generated: "" };
    status = "loading";
    renderServedExposure();
    const gen = ++loadGen;
    fetch(`/cases/${encodeURIComponent(caseId)}/served-exposure`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        exposure = d && Array.isArray(d.locations) ? d : { locations: [], generated: "" };
        status = "loaded";
        renderServedExposure();
      })
      .catch((err) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        exposure = { locations: [], generated: "", error: String((err && err.message) || err) };
        status = "error";
        renderServedExposure();
      });
  }

  window.loadServedExposure = loadServedExposure;
})();
