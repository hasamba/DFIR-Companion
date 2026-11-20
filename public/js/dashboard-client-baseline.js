// Client Baseline panel (#2670): the #sec-client-baseline section of a threat-hunt case.
//
// Link the case to a client profile, export the client's "please confirm" list (CSV / Markdown),
// mark candidates Approved / Not allowed / Unknown in bulk, import the client's filled CSV, and keep
// the client's blocked / approved download sources. Seeing a program never approves it: only a mark
// does, saved with who, when and its source. Editing a profile is the instance administrator's
// (the server answers 403 to anyone else); earlier hunts are listed only when the viewer may open them.
//
// Every server- or evidence-derived string is written with textContent, never innerHTML.
(function () {
  "use strict";

  const byId = (id) => document.getElementById(id);
  let baselineRenderGen = 0;

  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  }

  async function call(url, opts) {
    try {
      const res = await fetch(url, opts);
      let body = {};
      try {
        body = await res.json();
      } catch {
        body = {};
      }
      return { ok: res.ok, status: res.status, body };
    } catch (e) {
      return { ok: false, status: 0, body: { error: String((e && e.message) || e) } };
    }
  }

  const send = (method, url, body) =>
    call(url, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

  const huntUrl = (caseId, tail) => `/cases/${encodeURIComponent(caseId)}/hunt/${tail}`;
  const profileUrl = (pid, tail) => `/client-profiles/${encodeURIComponent(pid)}${tail ? `/${tail}` : ""}`;
  const failText = (r) => (r.status === 403 ? "only the instance administrator can edit a client profile" : r.body.error || r.status);

  function askSource() {
    const s = window.prompt("Source of this answer (for the audit log), e.g. “client email 2026-11-20”:", "");
    return s && s.trim() ? s.trim() : null;
  }

  async function linkRow(caseId, info, status) {
    const row = el("div", null, "cb-link");
    const list = await call("/client-profiles");
    const select = el("select");
    select.appendChild(el("option", "— pick a client —"));
    for (const p of list.ok && Array.isArray(list.body) ? list.body : []) {
      const o = el("option", p.name);
      o.value = p.id;
      if (info.client && info.client.id === p.id) o.selected = true;
      select.appendChild(o);
    }
    const link = el("button", "Link case to client");
    link.type = "button";
    link.addEventListener("click", async () => {
      if (!select.value || select.selectedIndex === 0) return;
      const r = await send("POST", huntUrl(caseId, "client"), { clientId: select.value });
      status.textContent = r.ok ? "Linked." : `Link failed: ${r.status === 403 ? "linking needs case administrator rights" : r.body.error || r.status}`;
      if (r.ok) loadClientBaseline(caseId);
    });
    const create = el("button", "New client…");
    create.type = "button";
    create.addEventListener("click", async () => {
      const name = window.prompt("Client name (e.g. “Client A”):", "");
      if (!name || !name.trim()) return;
      const r = await send("POST", "/client-profiles", { name: name.trim() });
      status.textContent = r.ok ? `Client “${r.body.name}” created — link it above.` : `Create failed: ${failText(r)}`;
      if (r.ok) loadClientBaseline(caseId);
    });
    row.append(el("label", "Client: "), select, link, create);
    return row;
  }

  function summary(caseId, info) {
    const box = el("div", null, "cb-summary");
    const c = info.client;
    box.appendChild(el("p", `${c.name} · baseline version ${info.currentVersion}${info.pinnedVersion !== null ? ` · this case graded against version ${info.pinnedVersion}` : ""} · ${info.pending} item(s) waiting for the client`));
    if (info.pinnedVersion !== null && info.currentVersion !== info.pinnedVersion)
      box.appendChild(el("p", "The baseline changed since this case was graded. Use “Re-grade with current baseline” in the Threat Hunt panel to apply it here.", "ev-sub"));
    if (c.defaultServerSetId) box.appendChild(el("p", `Default server set for new hunt cases: ${c.defaultServerSetId}`, "ev-sub"));
    const exports = el("p");
    for (const [fmt, label] of [["csv", "Export confirm list (CSV)"], ["md", "Export confirm list (Markdown)"]]) {
      const a = el("a", label);
      a.href = huntUrl(caseId, `confirm-list.${fmt}`);
      a.setAttribute("download", "");
      exports.append(a, document.createTextNode(" "));
    }
    box.appendChild(exports);
    if (info.earlierHunts && info.earlierHunts.length)
      box.appendChild(el("p", `Earlier hunts you can open: ${info.earlierHunts.map((h) => `${h.name} (${h.caseId})`).join(", ")}`, "ev-sub"));
    return box;
  }

  function candidatesTable(list, picked) {
    const table = el("table", null, "cb-candidates");
    const head = el("tr");
    for (const h of ["", "Program", "Path", "Hosts", "Evidence", "Publisher (unverified)", "Why pending"]) head.appendChild(el("th", h));
    table.appendChild(head);
    for (const c of list) {
      const tr = el("tr");
      const box = el("input");
      box.type = "checkbox";
      box.addEventListener("change", () => (box.checked ? picked.add(c) : picked.delete(c)));
      const td = el("td");
      td.appendChild(box);
      tr.appendChild(td);
      for (const v of [c.program, c.pathPattern || "(any)", `${c.hostCount}: ${c.hosts.join(", ")}`, c.evidence.join(", "), c.publishers.join(" | "), c.reason])
        tr.appendChild(el("td", v));
      table.appendChild(tr);
    }
    return table;
  }

  function markBar(caseId, pid, picked, status) {
    const bar = el("div", null, "cb-marks");
    for (const [verdict, label] of [["approved", "Mark Approved"], ["not-allowed", "Mark Not allowed"], ["unknown", "Reset to Unknown"]]) {
      const b = el("button", label);
      b.type = "button";
      b.addEventListener("click", async () => {
        if (!picked.size) return void (status.textContent = "Tick at least one item first.");
        const source = askSource();
        if (!source) return;
        const marks = [...picked].map((c) => ({ verdict, family: c.family, program: c.program, pathPattern: c.pathPattern, sha256: c.sha256 }));
        const r = await send("POST", profileUrl(pid, "marks"), { marks, source });
        status.textContent = r.ok ? `Saved as baseline version ${r.body.version}.` : `Save failed: ${failText(r)}`;
        if (r.ok) loadClientBaseline(caseId);
      });
      bar.appendChild(b);
    }
    const file = el("input");
    file.type = "file";
    file.accept = ".csv,text/csv";
    file.addEventListener("change", async () => {
      const f = file.files && file.files[0];
      if (!f) return;
      const source = askSource();
      if (!source) return;
      const r = await send("POST", profileUrl(pid, "marks/import"), { csv: await f.text(), source });
      status.textContent = r.ok ? `Imported ${r.body.imported} answer(s); ${r.body.skipped.length} row(s) skipped.` : `Import failed: ${failText(r)}`;
      if (r.ok) loadClientBaseline(caseId);
    });
    bar.append(el("span", " Import the client's filled CSV: "), file);
    return bar;
  }

  async function domainsEditor(pid, status) {
    const r = await call(profileUrl(pid));
    if (!r.ok) return el("p", "Blocked download categories and sites: editable by the instance administrator.", "ev-sub");
    const b = r.body.baseline || {};
    const box = el("div", null, "cb-domains");
    const area = (label, values) => {
      const t = el("textarea");
      t.rows = 2;
      t.value = (values || []).join("\n");
      t.setAttribute("aria-label", label);
      box.append(el("label", label), t);
      return t;
    };
    const cats = area("Blocked download categories (one per line: torrent, file-sharing, cloud-storage, paste-sites, remote-access)", b.blockedCategories);
    const blocked = area("Blocked download sites (domains; subdomains included)", b.blockedDomains);
    const approved = area("Approved download sources (domains)", b.approvedDomains);
    const save = el("button", "Save download policy");
    save.type = "button";
    const lines = (t) => t.value.split(/\s+/).map((x) => x.trim()).filter(Boolean);
    save.addEventListener("click", async () => {
      const source = askSource();
      if (!source) return;
      const w = await send("PUT", profileUrl(pid, "domains"), { blockedCategories: lines(cats), blockedDomains: lines(blocked), approvedDomains: lines(approved), source });
      status.textContent = w.ok ? `Saved as baseline version ${w.body.version}.` : `Save failed: ${failText(w)}`;
    });
    box.appendChild(save);
    return box;
  }

  async function loadClientBaseline(caseId) {
    const box = byId("clientBaselinePanel");
    if (!box || !caseId) return;
    const gen = ++baselineRenderGen;
    const st = await call(huntUrl(caseId, "status"));
    const info = st.ok && st.body.hunt ? await call(huntUrl(caseId, "client")) : null;
    if (gen !== baselineRenderGen) return;
    box.replaceChildren();
    if (!st.ok || !st.body.hunt) {
      box.appendChild(el("p", "Client baselines apply to threat-hunt cases only.", "ev-sub"));
      return;
    }
    const status = el("p", "", "ev-sub");
    if (!info || !info.ok) {
      box.appendChild(el("p", `Client baseline unavailable: ${(info && info.body.error) || "error"}`, "ev-sub"));
      return;
    }
    box.appendChild(await linkRow(caseId, info.body, status));
    if (info.body.client) {
      const pid = info.body.client.id;
      box.appendChild(summary(caseId, info.body));
      const cands = await call(huntUrl(caseId, "candidates"));
      const picked = new Set();
      if (cands.ok && cands.body.candidates.length) {
        box.appendChild(markBar(caseId, pid, picked, status));
        box.appendChild(candidatesTable(cands.body.candidates, picked));
      } else box.appendChild(el("p", "Nothing is waiting for the client's confirmation.", "ev-sub"));
      box.appendChild(await domainsEditor(pid, status));
    }
    box.appendChild(status);
  }

  window.loadClientBaseline = loadClientBaseline;
})();
