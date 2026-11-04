// Settings → Server sets: the list of named IRIS / Timesketch / Velociraptor sets and the set
// editor. Each case remembers one set; new cases use the default set.
//
// Set names come from analysts and may hold any text, so every name is written with textContent,
// never innerHTML. The server never sends a stored secret: it sends "••••••", and the editor sends
// that mask back unchanged, which tells the server to keep the stored value.
//
// Each Test button sends what the editor holds now, saved or not: a new set to /server-sets/test,
// a saved set to /server-sets/<id>/test, where a mask stands for the stored secret. A test saves
// nothing.
//
// fetchServerSets() is shared: the New Case picker and the case header's Change… dialog list the
// sets through it. It also paints every [data-server-set-default] label with the default set's name
// — the case-less actions (the fleet tab, the Settings connection checks) run on that set.
(function () {
  "use strict";

  // tool → [button id, result line id, the field the test needs, the hint while that field is empty]
  const TOOL_TESTS = {
    iris: ["sseTestIris", "sseTestIrisResult", "sseIrisUrl", "Enter the URL first"],
    timesketch: ["sseTestTs", "sseTestTsResult", "sseTsUrl", "Enter the URL first"],
    velociraptor: ["sseTestVelo", "sseTestVeloResult", "sseVeloConfig", "Enter the API config path first"],
  };
  const TOOL_LABELS = { iris: "IRIS", timesketch: "Timesketch", velociraptor: "Velociraptor" };
  // [input id, tool, field, kind]. The field names are the server's (routes/serverSetBody.ts).
  const FIELDS = [
    ["sseIrisUrl", "iris", "url"],
    ["sseIrisKey", "iris", "apiKey"],
    ["sseIrisCa", "iris", "ca"],
    ["sseIrisInsecure", "iris", "insecure", "bool"],
    ["sseIrisCustomer", "iris", "customerId"],
    ["sseIrisClassification", "iris", "classificationId"],
    ["sseTsUrl", "timesketch", "url"],
    ["sseTsUser", "timesketch", "user"],
    ["sseTsPassword", "timesketch", "password"],
    ["sseTsCa", "timesketch", "ca"],
    ["sseTsInsecure", "timesketch", "insecure", "bool"],
    ["sseTsTimeline", "timesketch", "timeline"],
    ["sseVeloConfig", "velociraptor", "apiConfigPath"],
    ["sseVeloOrg", "velociraptor", "org"],
    ["sseVeloGuiUrl", "velociraptor", "guiUrl"],
  ];

  let lastList = null; // the last GET /server-sets answer, with `editable`
  let editing = null; // the set open in the editor; null for a new set
  let editorOpts = {}; // { onSaved, closeOnSave } from the caller that opened the editor

  const byId = (id) => document.getElementById(id);

  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  }

  function setMsg(id, text, isError) {
    const box = byId(id);
    if (!box) return;
    box.textContent = text || "";
    box.style.color = isError ? "var(--badge-danger-text)" : "";
  }

  async function readJson(res) {
    try {
      return await res.json();
    } catch {
      return {};
    }
  }

  // Single-user mode has one operator, who is the administrator. In team mode only a global
  // administrator edits sets; the server sends everyone else names only.
  function isGlobalAdmin() {
    const auth = window.dfirAuthState;
    if (!auth || !auth.enabled) return true;
    return !!(auth.identity && auth.identity.globalRole === "administrator");
  }

  /** GET /server-sets, plus whether this user may edit the sets. */
  async function fetchServerSets() {
    const res = await fetch("/server-sets");
    const body = await readJson(res);
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    const sets = Array.isArray(body.sets) ? body.sets : [];
    // A names-only answer means the server treats this user as a member, whatever the page thinks.
    const fullAnswer = sets.every((s) => "usedBy" in s);
    lastList = { defaultId: body.defaultId || "", sets, editable: isGlobalAdmin() && fullAnswer };
    paintDefaultLabels(lastList);
    return lastList;
  }

  function paintDefaultLabels(list) {
    const def = list.sets.find((s) => s.id === list.defaultId);
    const text = def ? `Using server set: ${def.name}` : "Using server set: none";
    document.querySelectorAll("[data-server-set-default]").forEach((node) => {
      node.textContent = text;
    });
  }

  function toolsOf(set) {
    return Object.keys(TOOL_LABELS).filter((t) => set[t]);
  }

  function rowButton(label, onClick) {
    const b = el("button", label);
    b.type = "button";
    b.onclick = onClick;
    return b;
  }

  function renderRow(set, list) {
    const row = el("div", null, "server-set-row");
    row.setAttribute("role", "listitem");
    row.appendChild(el("strong", set.name, "server-set-name"));
    if (set.id === list.defaultId) row.appendChild(el("span", "default", "server-set-badge"));
    if (!list.editable) return row;
    const tools = toolsOf(set).map((t) => TOOL_LABELS[t]);
    row.appendChild(el("span", tools.length ? tools.join(" · ") : "no tools", "server-set-meta"));
    const n = Number(set.usedBy) || 0;
    row.appendChild(el("span", `Used by ${n} cases`, "server-set-meta"));
    const actions = el("span", null, "server-set-actions");
    actions.appendChild(rowButton("Edit", () => openServerSetEditor(set)));
    if (set.id !== list.defaultId) actions.appendChild(rowButton("Make default", () => makeDefault(set)));
    actions.appendChild(rowButton("Delete", () => deleteSet(set)));
    row.appendChild(actions);
    return row;
  }

  /** Renders the Settings list. */
  async function loadServerSets() {
    const box = byId("serverSetsList");
    if (!box) return;
    let list;
    try {
      list = await fetchServerSets();
    } catch (e) {
      setMsg("serverSetsMsg", `Server sets cannot be loaded: ${e.message}`, true);
      return;
    }
    box.textContent = "";
    for (const set of list.sets) box.appendChild(renderRow(set, list));
    if (list.sets.length === 0) box.appendChild(el("div", "No server sets yet.", "server-set-meta"));
    const add = byId("serverSetAddBtn");
    if (add) add.hidden = !list.editable;
    if (!list.editable) setMsg("serverSetsMsg", "Only an administrator can change server sets.");
  }

  async function makeDefault(set) {
    const res = await fetch(`/server-sets/${encodeURIComponent(set.id)}/default`, { method: "POST" });
    if (!res.ok) {
      const body = await readJson(res);
      setMsg("serverSetsMsg", body.error || `HTTP ${res.status}`, true);
      return;
    }
    setMsg("serverSetsMsg", "");
    await loadServerSets();
  }

  async function deleteSet(set) {
    if (!confirm(`Delete server set '${set.name}'?`)) return;
    const res = await fetch(`/server-sets/${encodeURIComponent(set.id)}`, { method: "DELETE" });
    if (res.ok) {
      setMsg("serverSetsMsg", "");
      await loadServerSets();
      return;
    }
    const body = await readJson(res);
    if (Array.isArray(body.usedBy) && body.usedBy.length) {
      const names = body.usedBy.map((c) => c.name || c.id).join(", ");
      setMsg("serverSetsMsg", `This set is in use by these cases: ${names}. Change their server set first.`, true);
      return;
    }
    setMsg("serverSetsMsg", body.error || `HTTP ${res.status}`, true);
  }

  // ── The editor ──────────────────────────────────────────────────────────────────────────────

  function fillEditor(set) {
    byId("sseName").value = set ? set.name || "" : "";
    for (const [id, tool, field, kind] of FIELDS) {
      const input = byId(id);
      if (!input) continue;
      const value = set && set[tool] ? set[tool][field] : undefined;
      if (kind === "bool") input.checked = value === true;
      else input.value = value === undefined || value === null ? "" : String(value);
    }
  }

  function readEditor() {
    const body = { name: byId("sseName").value.trim(), iris: {}, timesketch: {}, velociraptor: {} };
    for (const [id, tool, field, kind] of FIELDS) {
      const input = byId(id);
      if (!input) continue;
      // A secret field is sent as it stands: the mask keeps the stored value on the server.
      body[tool][field] = kind === "bool" ? !!input.checked : input.value.trim();
    }
    return body;
  }

  // Required fields per tool, as the server judges them (integrations/serverSets/types.ts).
  const REQUIRED = { iris: ["url", "apiKey"], timesketch: ["url", "user", "password"], velociraptor: ["apiConfigPath"] };

  /** One warning line per tool with some text but a required field empty. The save still goes. */
  function incompleteWarnings(body) {
    return Object.keys(REQUIRED)
      .filter((tool) => {
        const fields = body[tool] || {};
        const used = Object.values(fields).some((v) => typeof v === "string" && v !== "");
        return used && REQUIRED[tool].some((f) => !fields[f]);
      })
      .map((tool) => {
        const name = TOOL_LABELS[tool];
        return `${name} is incomplete: cases on this set cannot use ${name} until it is complete.`;
      });
  }

  // A tool's Test button waits for its URL (Velociraptor: its API config path). The values are
  // read on every check, so a value set with no event (Browse… does that) still counts.
  function syncTestButtons() {
    for (const [btnId, , fieldId, hint] of Object.values(TOOL_TESTS)) {
      const btn = byId(btnId);
      const field = byId(fieldId);
      if (!btn) continue;
      btn.disabled = !(field && field.value.trim());
      btn.title = btn.disabled ? hint : "";
    }
  }

  /** Opens the editor on `set`, or on a blank set when `set` is null. */
  function openServerSetEditor(set, opts) {
    editing = set && set.id ? set : null;
    editorOpts = opts || {};
    fillEditor(editing);
    const title = byId("serverSetEditorTitle");
    if (title) title.textContent = editing ? `Edit server set '${editing.name}'` : "New server set";
    setMsg("sseMsg", "");
    setMsg("sseTestResult", "");
    for (const [, resultId] of Object.values(TOOL_TESTS)) setMsg(resultId, "");
    syncTestButtons();
    byId("serverSetEditorOverlay").classList.add("open");
    byId("sseName").focus();
  }

  function closeEditor() {
    byId("serverSetEditorOverlay").classList.remove("open");
    editorOpts = {};
  }

  async function saveEditor() {
    const body = readEditor();
    if (!body.name) {
      setMsg("sseMsg", "A server set needs a name.", true);
      return;
    }
    const url = editing ? `/server-sets/${encodeURIComponent(editing.id)}` : "/server-sets";
    setMsg("sseMsg", "Saving…");
    let res;
    try {
      res = await fetch(url, {
        method: editing ? "PUT" : "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch (e) {
      setMsg("sseMsg", `Save failed: ${e.message}`, true);
      return;
    }
    const saved = await readJson(res);
    if (!res.ok) {
      setMsg("sseMsg", `Save failed: ${saved.error || `HTTP ${res.status}`}`, true);
      return;
    }
    editing = saved;
    fillEditor(saved);
    const warnings = incompleteWarnings(body);
    setMsg("sseMsg", ["Saved.", ...warnings].join(" "), warnings.length > 0);
    syncTestButtons();
    const { onSaved, closeOnSave } = editorOpts;
    await loadServerSets();
    if (typeof onSaved === "function") await onSaved(saved);
    if (closeOnSave) closeEditor();
  }

  /** POSTs the editor's values as they stand to the test route; `tools` limits the tools run. */
  async function postTest(tools) {
    const body = readEditor();
    if (tools) body.tools = tools;
    const url = editing ? `/server-sets/${encodeURIComponent(editing.id)}/test` : "/server-sets/test";
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const answer = await readJson(res);
    if (!res.ok) throw new Error(answer.error || `HTTP ${res.status}`);
    return answer;
  }

  async function testTool(tool) {
    const [btnId, resultId] = TOOL_TESTS[tool];
    syncTestButtons();
    if (byId(btnId).disabled) return;
    setMsg(resultId, "Testing…");
    try {
      const r = (await postTest([tool]))[tool];
      if (r && r.ok) setMsg(resultId, "Connected.");
      else setMsg(resultId, `Failed: ${(r && r.error) || "no result"}`, true);
    } catch (e) {
      setMsg(resultId, `Failed: ${e.message}`, true);
    }
  }

  // The bottom button: every filled-in tool, from the typed values too.
  async function testEditor() {
    setMsg("sseTestResult", "Testing…");
    let body;
    try {
      body = await postTest();
    } catch (e) {
      setMsg("sseTestResult", `Test failed: ${e.message}`, true);
      return;
    }
    const box = byId("sseTestResult");
    box.textContent = "";
    box.style.color = "";
    const tools = Object.keys(TOOL_LABELS).filter((t) => body[t]);
    if (tools.length === 0) box.appendChild(el("div", "This set has no tools to test."));
    for (const t of tools) {
      const r = body[t];
      box.appendChild(el("div", `${TOOL_LABELS[t]}: ${r.ok ? "connected" : r.error || "failed"}`));
    }
  }

  function initServerSets() {
    byId("serverSetAddBtn").onclick = () => openServerSetEditor(null);
    byId("sseSave").onclick = saveEditor;
    byId("sseTest").onclick = testEditor;
    for (const [tool, [btnId]] of Object.entries(TOOL_TESTS)) {
      const btn = byId(btnId);
      if (btn) btn.onclick = () => testTool(tool);
    }
    byId("sseClose").onclick = closeEditor;
    for (const id of ["sseName", ...FIELDS.map((f) => f[0])]) {
      const input = byId(id);
      if (!input) continue;
      input.addEventListener("input", syncTestButtons);
      input.addEventListener("change", syncTestButtons);
    }
    const overlay = byId("serverSetEditorOverlay");
    overlay.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeEditor();
    });
    // The API config path gets the same Browse… picker the setup wizard uses.
    if (typeof wirePathBrowseControls === "function") wirePathBrowseControls(overlay);
    document.querySelectorAll(".stab").forEach((tab) => {
      if (tab.dataset.stab === "integrations") tab.addEventListener("click", loadServerSets);
    });
    loadServerSets();
  }

  window.initServerSets = initServerSets;
  window.loadServerSets = loadServerSets;
  window.fetchServerSets = fetchServerSets;
  window.openServerSetEditor = openServerSetEditor;
})();
