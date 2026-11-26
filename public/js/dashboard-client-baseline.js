// Client Baseline panel (#2670): the #sec-client-baseline section of a threat-hunt case.
//
// Link the case to a client profile, export the client's "please confirm" list (CSV / Markdown),
// mark candidates Approved / Not allowed / Unknown in bulk, import the client's filled CSV, and keep
// the client's blocked / approved download sources. Seeing a program never approves it: only a mark
// does, saved with who, when and its source. Editing a profile is the instance administrator's
// (the server answers 403 to anyone else); earlier hunts are listed only when the viewer may open them.
// Creating, editing, archiving and deleting a client (#2941) are shown to the administrator only.
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
  const NO_PATH_LABEL = "(no path — cannot be approved)";
  const SKIPPED_SHOWN = 5;
  /** " Skipped: line 2: <reason>; …" for the first few skipped CSV rows, or "" when none. */
  const skippedText = (skipped) => {
    if (!Array.isArray(skipped) || !skipped.length) return "";
    const shown = skipped.slice(0, SKIPPED_SHOWN).map((s) => `line ${s.line}: ${s.reason}`).join("; ");
    const more = skipped.length > SKIPPED_SHOWN ? ` (+${skipped.length - SKIPPED_SHOWN} more)` : "";
    return ` Skipped: ${shown}${more}`;
  };

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

  // #2941: client management is the instance administrator's (js/dashboard-client-admin.js).
  const isAdmin = () => typeof isClientAdmin === "function" && typeof clientAdminBar === "function" && isClientAdmin();
  const optionLabel = (c) => `${c.name}${c.archived ? " (archived)" : ""}`;
  let showArchived = false; // the administrator's "Show archived clients" tick box

  async function linkRow(caseId, info, status) {
    const admin = isAdmin();
    const list = await call(admin && showArchived ? "/client-profiles?includeArchived=1" : "/client-profiles");
    const clients = list.ok && Array.isArray(list.body) ? list.body.slice() : [];
    // An archived client stays visible while this case is linked to it, so the box shows the real link.
    if (info.client && !clients.some((p) => p.id === info.client.id)) clients.push(info.client);
    const select = el("select", null, "toolbar-select");
    select.id = "cbClientSelect";
    select.appendChild(el("option", "— pick a client —")).value = "";
    for (const p of clients) {
      const o = el("option", optionLabel(p));
      o.value = p.id;
      if (info.client && info.client.id === p.id) o.selected = true;
      select.appendChild(o);
    }
    if (info.client) select.value = info.client.id;
    const link = button("Link case to client");
    link.addEventListener("click", async () => {
      if (!select.value) return;
      const picked = clients.find((p) => p.id === select.value);
      if (picked && picked.archived) return void (status.textContent = "This client is archived. Unarchive it before linking a case to it.");
      const r = await send("POST", huntUrl(caseId, "client"), { clientId: select.value });
      status.textContent = r.ok ? "Linked." : `Link failed: ${r.status === 403 ? "linking needs case administrator rights" : r.body.error || r.status}`;
      if (r.ok) loadClientBaseline(caseId);
    });
    const controls = el("div", null, "cb-link-row");
    controls.append(select, link);
    if (admin) {
      // #2735/#2941: creating a client is the instance administrator's, as in the New Case dialog.
      const create = button("New client…");
      create.addEventListener("click", async () => {
        const name = window.prompt("Client name (e.g. “Client A”):", "");
        if (!name || !name.trim()) return;
        const r = await send("POST", "/client-profiles", { name: name.trim() });
        status.textContent = r.ok ? `Client “${r.body.name}” created — link it above.` : `Create failed: ${failText(r)}`;
        if (r.ok) loadClientBaseline(caseId, status.textContent);
      });
      controls.appendChild(create);
    }
    const row = field("Client", controls);
    row.classList.add("cb-link");
    row.querySelector("label").htmlFor = select.id;
    const bar = admin
      ? clientAdminBar({
          select,
          clients,
          status,
          showArchived,
          onToggleArchived: (on) => {
            showArchived = on;
            loadClientBaseline(caseId);
          },
          onChanged: (note) => loadClientBaseline(caseId, note),
        })
      : null;
    if (bar) row.appendChild(bar);
    return row;
  }

  function summary(caseId, info) {
    const box = el("div", null, "cb-summary");
    const c = info.client;
    box.appendChild(el("p", `${optionLabel(c)} · baseline version ${info.currentVersion}${info.pinnedVersion !== null ? ` · this case graded against version ${info.pinnedVersion}` : ""} · ${info.pending} item(s) waiting for the client`));
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
    box.appendChild(el("p", "Filled automatically from this case's hunt results (programs, autoruns and downloads the client has not confirmed yet, rarest first) — nothing to type. Send the confirm list to the client and mark their answers below; the answers carry over to the client's next hunt cases.", "ev-sub cb-auto-hint"));
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
      // No path = nothing an approval can match (#2747); the box stays usable, Not allowed still works.
      for (const v of [c.program, c.pathPattern || NO_PATH_LABEL,`${c.hostCount}: ${c.hosts.join(", ")}`, c.evidence.join(", "), c.publishers.join(" | "), c.reason])
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
        // An approval with no path could never match and the server refuses it (#2747): leave those out and say why.
        const chosen = verdict === "approved" ? [...picked].filter((c) => c.pathPattern) : [...picked];
        const left = picked.size - chosen.length;
        const why = left ? `${left} item(s) have no file path or hash and cannot be approved; mark them Not allowed or approve their files instead.` : "";
        if (!chosen.length) return void (status.textContent = why);
        const source = askSource();
        if (!source) return;
        // The hashes (SHA-256 and the usable Amcache SHA1) and the verified signer go with the mark, or an approval could never match (#2731).
        const marks = chosen.map((c) => ({
          verdict,
          family: c.family,
          program: c.program,
          pathPattern: c.pathPattern,
          sha256: c.sha256 || [],
          sha1: c.sha1 || [],
          ...(c.approvableSigner ? { signer: c.approvableSigner } : {}),
        }));
        const r = await send("POST", profileUrl(pid, "marks"), { marks, source });
        const text = [r.ok ? `Saved as baseline version ${r.body.version}.` : `Save failed: ${failText(r)}`, why].filter(Boolean).join(" ");
        status.textContent = text;
        if (r.ok) loadClientBaseline(caseId, text);
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
      // Name why rows were skipped (e.g. an Approved row with no path, #2747), on success and on a refusal alike.
      const said = r.ok ? `Imported ${r.body.imported} answer(s); ${r.body.skipped.length} row(s) skipped.` : `Import failed: ${failText(r)}.`;
      const text = `${said}${skippedText(r.body.skipped)}`;
      status.textContent = text;
      if (r.ok) loadClientBaseline(caseId, text);
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
    box.appendChild(el("h3", "Download policy (optional)", "cb-policy-title"));
    box.appendChild(
      el(
        "p",
        "Downloads from a blocked category or a blocked site are graded as policy violations; runnable or archive files (.exe, .msi, .zip …) downloaded from anywhere other than an approved source, or with no recorded source, are flagged.",
        "cb-policy-note",
      ),
    );
    box.appendChild(
      el(
        "p",
        "Typed in by you, from the client's own rules — never filled automatically. The grey text is only an example. Leave it empty if the client has no download policy: nothing is graded as a policy violation and the rest of the hunt works as usual.",
        "cb-policy-note cb-manual-hint",
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

  /** `note` is shown in the fresh status line, so a message said before a reload is not lost. */
  // #2904: is `caseId` still the case on screen? Fails open when there is no #caseId to read.
  function baselineOnScreen(caseId) {
    const el = byId("caseId");
    return !el || typeof el.value !== "string" || el.value.trim() === caseId;
  }
  // #2904: a load for another case blanks the previous case's panel at once. Every await below is
  // followed by a check that this render is still the newest for the case on screen: an older
  // render used to go on appending into the box after a newer one had cleared it.
  let baselineCase = null;
  // #2915: a cancelled or failed case load blanks the panel and retires any render still running; the
  // next open — the same case included — renders it again.
  function onBaselineReset(caseId) {
    if (caseId !== null) return;
    baselineRenderGen++;
    baselineCase = null;
    const box = byId("clientBaselinePanel");
    if (box) box.replaceChildren();
  }
  async function loadClientBaseline(caseId, note = "") {
    const box = byId("clientBaselinePanel");
    if (!box || !caseId) return;
    if (!baselineOnScreen(caseId)) return; // a late caller for a case the analyst has left
    typeof DfirPanelDefer !== "undefined" && typeof DfirPanelDefer.onReset === "function" && DfirPanelDefer.onReset(onBaselineReset);
    if (baselineCase !== caseId) {
      baselineCase = caseId;
      box.replaceChildren();
    }
    const gen = ++baselineRenderGen;
    const live = () => gen === baselineRenderGen && baselineOnScreen(caseId);
    const st = await call(huntUrl(caseId, "status"));
    const info = st.ok && st.body.hunt ? await call(huntUrl(caseId, "client")) : null;
    if (!live()) return;
    box.replaceChildren();
    if (!st.ok || !st.body.hunt) {
      box.appendChild(el("p", "Client baselines apply to threat-hunt cases only.", "ev-sub"));
      return;
    }
    const status = el("p", note, "ev-sub");
    if (!info || !info.ok) {
      box.appendChild(el("p", `Client baseline unavailable: ${(info && info.body.error) || "error"}`, "ev-sub"));
      return;
    }
    const row = await linkRow(caseId, info.body, status);
    if (!live()) return;
    box.appendChild(row);
    if (info.body.client) {
      const pid = info.body.client.id;
      box.appendChild(summary(caseId, info.body));
      const cands = await call(huntUrl(caseId, "candidates"));
      if (!live()) return;
      const picked = new Set();
      if (cands.ok && cands.body.candidates.length) {
        box.appendChild(markBar(caseId, pid, picked, status));
        box.appendChild(candidatesTable(cands.body.candidates, picked));
      } else box.appendChild(el("p", "Nothing is waiting for the client's confirmation yet. Items appear here after a hunt imports program, autorun or download evidence (for example the Threat Hunt Starter bundle).", "ev-sub"));
      const editor = await domainsEditor(pid, status);
      if (!live()) return;
      box.appendChild(editor);
    }
    box.appendChild(status);
  }

  window.loadClientBaseline = loadClientBaseline;
})();
