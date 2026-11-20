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

  // The bundled download-categories list (companion/data/hunt/download-categories.json), id → plain
  // label. The ids are the stored values; a test keeps this table in step with the JSON file.
  const DOWNLOAD_CATEGORY_LABELS = [
    ["torrent", "Torrent"],
    ["file-sharing", "File sharing"],
    ["cloud-storage", "Cloud storage"],
    ["paste-sites", "Paste sites"],
    ["remote-access", "Remote access"],
  ];
  const DOMAIN_HINT = "One domain per line; subdomains are included.";

  function button(text) {
    const b = el("button", text, "ev-bulk-btn");
    b.type = "button";
    return b;
  }

  /** A labelled field: the label above its control, an optional hint below (the Settings .sfield look). */
  function field(labelText, control, hint) {
    const box = el("div", null, "sfield");
    const label = el("label", labelText);
    if (control.id) label.htmlFor = control.id;
    box.append(label, control);
    if (hint) box.appendChild(el("span", hint, "sfield-hint"));
    return box;
  }

  function askSource() {
    const s = window.prompt("Source of this answer (for the audit log), e.g. “client email 2026-11-20”:", "");
    return s && s.trim() ? s.trim() : null;
  }

  async function linkRow(caseId, info, status) {
    const list = await call("/client-profiles");
    const select = el("select", null, "toolbar-select");
    select.id = "cbClientSelect";
    select.appendChild(el("option", "— pick a client —"));
    for (const p of list.ok && Array.isArray(list.body) ? list.body : []) {
      const o = el("option", p.name);
      o.value = p.id;
      if (info.client && info.client.id === p.id) o.selected = true;
      select.appendChild(o);
    }
    const link = button("Link case to client");
    link.addEventListener("click", async () => {
      if (!select.value || select.selectedIndex === 0) return;
      const r = await send("POST", huntUrl(caseId, "client"), { clientId: select.value });
      status.textContent = r.ok ? "Linked." : `Link failed: ${r.status === 403 ? "linking needs case administrator rights" : r.body.error || r.status}`;
      if (r.ok) loadClientBaseline(caseId);
    });
    const create = button("New client…");
    create.addEventListener("click", async () => {
      const name = window.prompt("Client name (e.g. “Client A”):", "");
      if (!name || !name.trim()) return;
      const r = await send("POST", "/client-profiles", { name: name.trim() });
      status.textContent = r.ok ? `Client “${r.body.name}” created — link it above.` : `Create failed: ${failText(r)}`;
      if (r.ok) loadClientBaseline(caseId);
    });
    const controls = el("div", null, "cb-link-row");
    controls.append(select, link, create);
    const row = field("Client", controls);
    row.classList.add("cb-link");
    row.querySelector("label").htmlFor = select.id;
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
      exports.append(a, " ");
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
      const b = button(label);
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
    file.hidden = true;
    file.addEventListener("change", async () => {
      const f = file.files && file.files[0];
      if (!f) return;
      const source = askSource();
      if (!source) return;
      const r = await send("POST", profileUrl(pid, "marks/import"), { csv: await f.text(), source });
      status.textContent = r.ok ? `Imported ${r.body.imported} answer(s); ${r.body.skipped.length} row(s) skipped.` : `Import failed: ${failText(r)}`;
      if (r.ok) loadClientBaseline(caseId);
    });
    const pick = button("Import the client's filled CSV…");
    pick.addEventListener("click", () => file.click());
    bar.append(pick, file);
    return bar;
  }

  /** Tick boxes for the bundled categories; a stored id outside the list stays as its own ticked box, so a save never drops it. */
  function categoryBoxes(stored) {
    const ids = DOWNLOAD_CATEGORY_LABELS.map(([id]) => id);
    const extra = stored.filter((id) => !ids.includes(id)).map((id) => [id, id]);
    const wrap = el("div", null, "cb-cats");
    const boxes = [];
    for (const [id, label] of [...DOWNLOAD_CATEGORY_LABELS, ...extra]) {
      const box = el("input");
      box.type = "checkbox";
      box.value = id;
      box.checked = stored.includes(id);
      const lab = el("label");
      lab.append(box, label);
      wrap.appendChild(lab);
      boxes.push(box);
    }
    const group = el("div", null, "sfield");
    group.append(el("label", "Blocked categories"), wrap);
    group.appendChild(el("span", "Each category is the bundled list of known sites of that kind.", "sfield-hint"));
    return { group, boxes };
  }

  function domainArea(id, label, values, example) {
    const t = el("textarea");
    t.id = id;
    t.rows = 3;
    t.placeholder = example;
    t.value = (values || []).join("\n");
    return { node: field(label, t, DOMAIN_HINT), area: t };
  }

  async function domainsEditor(pid, status) {
    const r = await call(profileUrl(pid));
    if (!r.ok) return el("p", "Blocked download categories and sites: editable by the instance administrator.", "ev-sub");
    const b = r.body.baseline || {};
    const box = el("div", null, "cb-policy");
    box.appendChild(el("h3", "Download policy", "cb-policy-title"));
    box.appendChild(
      el(
        "p",
        "Downloads from a blocked category or a blocked site are graded as policy violations; runnable or archive files (.exe, .msi, .zip …) downloaded from anywhere other than an approved source, or with no recorded source, are flagged.",
        "cb-policy-note",
      ),
    );
    const cats = categoryBoxes(b.blockedCategories || []);
    const blocked = domainArea("cbBlockedSites", "Blocked sites", b.blockedDomains, "files.example\nshare.example");
    const approved = domainArea("cbApprovedSources", "Approved download sources", b.approvedDomains, "downloads.example\nupdates.example");
    const save = button("Save download policy");
    const lines = (t) => t.value.split(/\s+/).map((x) => x.trim()).filter(Boolean);
    save.addEventListener("click", async () => {
      const source = askSource();
      if (!source) return;
      const blockedCategories = cats.boxes.filter((x) => x.checked).map((x) => x.value);
      const w = await send("PUT", profileUrl(pid, "domains"), { blockedCategories, blockedDomains: lines(blocked.area), approvedDomains: lines(approved.area), source });
      status.textContent = w.ok ? `Saved as baseline version ${w.body.version}.` : `Save failed: ${failText(w)}`;
    });
    box.append(cats.group, blocked.node, approved.node, save);
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
