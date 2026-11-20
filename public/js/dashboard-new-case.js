// New case creation — the modal that names a case, picks a template and seeds the demo case
// (#415 tier 3).
//
// ITS BANNER IS 692 LINES AND 595 OF THEM ARE NOT THIS FEATURE. What follows the five functions
// here is the page's long run of load-time wiring, and NINETEEN guard stanzas from earlier
// extractions are threaded through it — the accumulated residue of this refactor landing its
// replacements in one region. Only this feature's own eight wiring lines came with it; everything
// else stays exactly where it is.
//
// onTemplateSelectChange is the page's, not this module's, so the ncTemplate binding reaches out
// for it the way eleven other modules reach for page functions.
(function () {
  // ── New case ── creation lives here (the extension only attaches to existing cases) ──
  async function openNewCase() {
    const idInput = document.getElementById("ncCaseId");
    idInput.value = "";
    document.getElementById("ncName").value = "";
    document.getElementById("ncInvestigator").value = (
      localStorage.getItem("dfir.investigator") || ""
    ).trim();
    document.getElementById("ncMsg").textContent = "";
    document.getElementById("ncTemplateDesc").style.display = "none";
    const mainSourcePick = document.getElementById("ncMainSource");
    if (mainSourcePick) mainSourcePick.value = ""; // #2594 — Automatic by default
    populateTemplateSelect(); // async, fills while user edits fields
    serverSetChosen = false; // a fresh dialog: no server set picked by the analyst yet
    serverSetsReady = populateServerSetSelect(); // async too; preselects the default server set
    populateHuntClients(); // #2670: the threat-hunt client picker (shown for a hunt type only)
    document.getElementById("newCaseOverlay").classList.add("open");
    // Auto-suggest the next incident id — still fully editable (focus + select so a
    // manually-typed id overtypes it in one keystroke).
    idInput.value = await suggestCaseId();
    idInput.focus();
    idInput.select();
  }
  // Next free INC-YYYY-NNN, from the server. This used to be computed here from /cases, which
  // could only see live, visible cases — so it happily reissued the number of a case that had been
  // deleted, and the new case then inherited its predecessor's orphaned background jobs. The
  // server also counts archived cases and ids retired by a delete. Falls back to a date+time id if
  // the request fails, so the field is never left blank.
  async function suggestCaseId() {
    const year = new Date().getFullYear();
    try {
      const res = await fetch("/api/next-case-id");
      if (!res.ok) throw new Error(`next-case-id: ${res.status}`);
      const { caseId } = await res.json();
      if (!caseId) throw new Error("next-case-id: empty");
      return caseId;
    } catch {
      const d = new Date(),
        p = (n) => String(n).padStart(2, "0");
      return `INC-${year}-${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
    }
  }
  // The "Servers" picker: every server set, the default preselected. The last entry opens the set
  // editor, and the set saved there becomes the pick. Names go in with textContent: an analyst
  // typed them. Members see no "+ New" entry — only an administrator can create a set.
  const NEW_SET = "__new__";
  let lastServerSet = "";
  async function populateServerSetSelect(selectId) {
    const select = document.getElementById("ncServerSet");
    if (!select || typeof fetchServerSets !== "function") return;
    select.textContent = "";
    const add = (value, label) => {
      const opt = document.createElement("option");
      opt.value = value;
      opt.textContent = label;
      select.appendChild(opt);
    };
    try {
      const list = await fetchServerSets();
      for (const set of list.sets) add(set.id, set.name);
      if (list.editable) add(NEW_SET, "+ Create a new server set…");
      select.value = selectId || list.defaultId;
    } catch {
      add("", "Default server set"); // the server links a case with no serverSetId to the default
      select.value = "";
    }
    lastServerSet = select.value;
  }
  function onServerSetChange() {
    serverSetChosen = true; // the analyst's own pick: a client's default never overrides it
    const select = document.getElementById("ncServerSet");
    if (select.value !== NEW_SET) {
      lastServerSet = select.value;
      return;
    }
    select.value = lastServerSet; // stays on the previous pick unless a new set is saved
    openServerSetEditor(null, {
      closeOnSave: true,
      onSaved: (set) => populateServerSetSelect(set.id),
    });
  }
  // Threat-hunt client (#2670, D5). A client is its own record; its default server set only
  // PRE-FILLS the Servers picker of a new hunt case. The analyst's own pick always wins, an
  // existing case never changes, and no host membership is inferred. Names go in with textContent.
  let serverSetChosen = false;
  let serverSetsReady = Promise.resolve();
  let huntClients = [];
  // #2735: "New client…" at the end of the box, for the instance administrator only (the create
  // route is admin-only). Single-user mode has one operator, who is the administrator.
  const NEW_CLIENT = "__new_client__";
  let huntClientCreate = false; // the list loaded AND this user may create a client
  let lastHuntClient = ""; // the pick to fall back to when a create is cancelled or fails
  function isInstanceAdmin() {
    const auth = window.dfirAuthState;
    if (!auth || !auth.enabled) return true;
    return !!(auth.identity && auth.identity.globalRole === "administrator");
  }
  function isHuntPick() {
    const p = typeof selectedNewCasePlaybook === "function" ? selectedNewCasePlaybook() : null;
    return !!(p && p.kind === "type" && p.def && p.def.mode === "hunt");
  }
  function syncHuntClientRow() {
    const row = document.getElementById("ncHuntClientRow");
    if (row) row.hidden = !(isHuntPick() && (huntClients.length || huntClientCreate));
  }
  async function populateHuntClients() {
    const select = document.getElementById("ncHuntClient");
    if (!select) return;
    huntClients = [];
    huntClientCreate = false;
    try {
      const res = await fetch("/client-profiles"); // 403 on the public demo: no picker
      const list = res.ok ? await res.json() : [];
      huntClients = Array.isArray(list) ? list : [];
      huntClientCreate = res.ok && isInstanceAdmin();
    } catch {
      huntClients = [];
    }
    select.textContent = "";
    const rows = [["", "No client"], ...huntClients.map((c) => [c.id, c.name])];
    if (huntClientCreate) rows.push([NEW_CLIENT, "New client…"]);
    for (const [value, label] of rows) select.appendChild(clientOption(value, label));
    select.value = lastHuntClient = "";
    syncHuntClientRow();
  }
  function clientOption(value, label) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = label;
    return opt;
  }
  // Ask for a name, create the client, and select it. A new client has no default server set, so
  // the Servers picker stays as it is. On cancel or failure the previous pick comes back.
  async function createHuntClient(select) {
    select.value = lastHuntClient;
    const name = (window.prompt("Client name (e.g. “Client A”):", "") || "").trim();
    if (!name) return;
    const msg = document.getElementById("ncMsg");
    let error = "";
    try {
      const res = await fetch("/client-profiles", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name }),
      });
      const body = await res.json().catch(() => ({}));
      if (res.ok && body.id) {
        huntClients = [...huntClients, body];
        const newOpt = select.options[select.options.length - 1];
        select.appendChild(clientOption(body.id, body.name || name));
        select.appendChild(newOpt); // "New client…" stays last
        select.value = lastHuntClient = body.id;
        msg.textContent = `Client “${body.name || name}” created.`;
        return;
      }
      error = res.status === 403 ? "only the instance administrator can edit a client profile" : body.error || "HTTP " + res.status;
    } catch (err) {
      error = err.message;
    }
    msg.textContent = `Client create failed: ${error}`;
  }
  // The picked client's id, only while the picked type is a threat hunt.
  function pickedHuntClient() {
    const select = document.getElementById("ncHuntClient");
    return select && select.value && isHuntPick() ? select.value : "";
  }
  async function onHuntClientChange() {
    const select = document.getElementById("ncHuntClient");
    if (select.value === NEW_CLIENT) return createHuntClient(select);
    lastHuntClient = select.value;
    await serverSetsReady; // both lists loaded before the pre-fill
    const client = huntClients.find((c) => c.id === pickedHuntClient());
    const want = client && client.defaultServerSetId;
    const sets = document.getElementById("ncServerSet");
    if (serverSetChosen || !want || !sets || ![...sets.options].some((o) => o.value === want)) return;
    sets.value = want;
    lastServerSet = want;
  }
  // Link the new case to its client; the case already exists, so a failure is said, not fatal.
  async function linkHuntClient(caseId, clientId) {
    let error = "";
    try {
      const res = await fetch(`/cases/${encodeURIComponent(caseId)}/hunt/client`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ clientId }),
      });
      if (!res.ok) error = ((await res.json().catch(() => ({}))).error || "HTTP " + res.status);
    } catch (err) {
      error = err.message;
    }
    if (error) alert(`The case was created, but linking it to the client failed: ${error}. Link it in the Client Baseline panel.`);
  }
  function closeNewCase() {
    document.getElementById("newCaseOverlay").classList.remove("open");
  }
  async function createNewCase() {
    const caseId = document.getElementById("ncCaseId").value.trim();
    const name = document.getElementById("ncName").value.trim();
    const investigator = document.getElementById("ncInvestigator").value.trim();
    const picked = selectedNewCasePlaybook();
    const serverSet = document.getElementById("ncServerSet");
    const serverSetId =
      serverSet && serverSet.value && serverSet.value !== NEW_SET ? serverSet.value : undefined;
    const huntClientId = pickedHuntClient();
    const mainSourceEl = document.getElementById("ncMainSource");
    const mainSource = mainSourceEl ? mainSourceEl.value : "";
    const msg = document.getElementById("ncMsg");
    if (!caseId || !name) {
      msg.textContent = "case id and name are required";
      return;
    }
    msg.textContent = "creating…";
    try {
      const res = await fetch("/cases", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          caseId,
          name,
          investigator: investigator || "unknown",
          aiProvider: null,
          templateId: picked.kind === "tpl" ? picked.id : undefined,
          incidentTypeId: picked.kind === "type" ? picked.id : undefined,
          serverSetId, // undefined → the server links the default set
          mainSource: mainSource || undefined, // #2594 — blank = Automatic (from evidence)
        }),
      });
      if (res.status === 201) {
        const created = await res.json().catch(() => ({}));
        // #2594: the case exists even when its picked main source could not be saved — say so.
        if (created.mainSourceError)
          alert(created.mainSourceError.charAt(0).toUpperCase() + created.mainSourceError.slice(1) + ".");
        if (huntClientId) await linkHuntClient(caseId, huntClientId);
        closeNewCase();
        // A pick; connect() below loads it and only then does #caseId change (#2399).
        if (typeof setCasePick === "function") setCasePick(caseId);
        else document.getElementById("caseId").value = caseId;
        loadCaseList(); // add the new case to the combo box
        connect(); // attach the dashboard to the case we just created
      } else if (res.status === 409) {
        msg.textContent =
          "a case with that id already exists — pick a different id, or Cancel and Connect to it";
      } else {
        const body = await res.json().catch(() => ({}));
        msg.textContent =
          "create failed: HTTP " +
          res.status +
          (body.error ? " — " + body.error : "");
      }
    } catch (err) {
      msg.textContent =
        "create failed: " + err.message + " — is the companion running?";
    }
  }

  async function loadDemoCase() {
    const btn = document.getElementById("seedDemoBtn");
    const orig = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Loading…";
    try {
      let res = await fetch("/cases/seed-demo", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      if (res.status === 409) {
        if (!confirm("Demo case already exists. Overwrite it?")) {
          btn.disabled = false;
          btn.textContent = orig;
          return;
        }
        res = await fetch("/cases/seed-demo", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ force: true }),
        });
      }
      if (!res.ok) {
        const b = await res.json().catch(() => ({}));
        alert("Demo case error: " + (b.error || "HTTP " + res.status));
      } else {
        const { caseId } = await res.json();
        // A pick; connect() below loads it and only then does #caseId change (#2399).
        if (typeof setCasePick === "function") setCasePick(caseId);
        else document.getElementById("caseId").value = caseId;
        loadCaseList();
        connect();
      }
    } catch (err) {
      alert("Demo case error: " + err.message + " — is the companion running?");
    } finally {
      btn.disabled = false;
      btn.textContent = orig;
    }
  }

  // The eight lines this feature owns in the page's wiring run.
  function initNewCase() {
    document.getElementById("newCaseBtn").onclick = openNewCase;
    document.getElementById("seedDemoBtn").onclick = loadDemoCase;
    document.getElementById("ncCreate").onclick = createNewCase;
    document.getElementById("ncCancel").onclick = closeNewCase;
    document.getElementById("ncTemplate").onchange = onTemplateSelectChange;
    document.getElementById("ncServerSet").onchange = onServerSetChange;
    document.getElementById("ncTemplate").addEventListener("change", syncHuntClientRow);
    const huntClient = document.getElementById("ncHuntClient");
    if (huntClient) huntClient.onchange = onHuntClientChange;
    document.getElementById("newCaseOverlay").addEventListener("click", (e) => {
      if (e.target.id === "newCaseOverlay") closeNewCase();
    });
    ["ncCaseId", "ncName", "ncInvestigator"].forEach((id) =>
      document.getElementById(id).addEventListener("keydown", (e) => {
        if (e.key === "Enter") createNewCase();
      }),
    );
  }

  window.openNewCase = openNewCase;
  window.closeNewCase = closeNewCase;
  window.createNewCase = createNewCase;
  window.loadDemoCase = loadDemoCase;
  window.initNewCase = initNewCase;
})();
