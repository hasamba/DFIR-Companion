// The open case's server set: the "Servers: <set name>" label beside the case picker, the
// "Change…" button and its two dialogs, and the gating of the IRIS / Timesketch / Velociraptor
// controls by the tools that set uses.
//
// ONE WRITER FOR THE TOOL FLAGS. With a case open, GET /cases/:id/server-set decides which tools
// the dashboard offers. With no case open, the default set decides (the /health flags). Every
// other writer — the /health poll, the Settings connection checks, the Push menu's status checks —
// asks caseToolEnabled(), so a default-set answer can never re-enable a tool the open case lacks.
//
// Set names and IRIS case names are written with textContent only: they come from analysts and
// from IRIS.
(function () {
  "use strict";

  const PUSH_OPTIONS = {
    iris: [["iris", "Push to DFIR-IRIS"]],
    timesketch: [
      ["timesketch", "Timesketch export (Forensic Timeline)"],
      ["timesketch-super", "Timesketch export (Super Timeline)"],
    ],
  };
  const NOTE = "Nothing on the old servers is deleted. Evidence in this case is kept.";

  // The case the header describes. tools is null while its answer is outstanding.
  let current = { caseId: "", setId: "", tools: null };
  let defaults = { velociraptor: false, iris: false, timesketch: false }; // the /health flags
  let pendingSetId = ""; // the set the confirm dialog will attach

  const byId = (id) => document.getElementById(id);

  async function readJson(res) {
    try {
      return await res.json();
    } catch {
      return {};
    }
  }

  function plural(n, one, many) {
    return `${n} ${n === 1 ? one : many}`;
  }

  /**
   * Whether the dashboard offers `tool`. With a case open, the case's own set decides. With no case
   * open, `fallback` (a fresh default-set answer) or the last /health flag decides.
   */
  function caseToolEnabled(tool, fallback) {
    if (current.caseId) return Array.isArray(current.tools) && current.tools.includes(tool);
    return fallback === undefined ? !!defaults[tool] : !!fallback;
  }

  /** The default set's tool flags, from /health. Used only while no case is open. */
  function setDefaultServerTools(health) {
    const h = health || {};
    defaults = {
      velociraptor: !!h.velociraptorEnabled,
      iris: !!h.irisEnabled,
      timesketch: !!h.timesketchEnabled,
    };
    applyCaseTools();
  }

  function syncPushOptions() {
    const select = byId("pushSelect");
    if (!select) return;
    for (const [tool, options] of Object.entries(PUSH_OPTIONS)) {
      const on = caseToolEnabled(tool);
      for (const [value, label] of options) {
        const existing = [...select.options].find((o) => o.value === value);
        if (on && !existing) {
          const opt = document.createElement("option");
          opt.value = value;
          opt.textContent = label;
          select.appendChild(opt);
        } else if (!on && existing) existing.remove();
      }
    }
    const hasTarget = [...select.options].some((o) => o.value);
    select.style.display = hasTarget ? "" : "none";
  }

  function applyCaseTools() {
    veloEnabled = caseToolEnabled("velociraptor");
    if (typeof applyVeloEnabled === "function") applyVeloEnabled();
    syncPushOptions();
  }

  // Single-user mode: the one operator administers every case. Team mode: a global administrator,
  // or the case's own administrator. The server checks again; this only hides a button that would 403.
  function canAdministerCase(caseId) {
    const auth = window.dfirAuthState;
    if (!auth || !auth.enabled) return true;
    if (auth.identity && auth.identity.globalRole === "administrator") return true;
    return !!(auth.caseRoles && auth.caseRoles[caseId] === "administrator");
  }

  function paintLabel(text, error) {
    const label = byId("caseServersLabel");
    if (!label) return;
    label.textContent = text;
    label.title = error || "";
    label.classList.toggle("case-servers-error", !!error);
    label.hidden = false;
  }

  /** Reads the open case's set and re-gates the tool controls. Called on every case switch. */
  async function refreshCaseServers(caseId) {
    const id = caseId || (byId("caseId") ? byId("caseId").value.trim() : "");
    current = { caseId: id, setId: "", tools: id ? null : [] };
    const change = byId("caseServersChangeBtn");
    if (!id) {
      const label = byId("caseServersLabel");
      if (label) label.hidden = true;
      if (change) change.hidden = true;
      applyCaseTools();
      return;
    }
    applyCaseTools(); // hide the tools until the case's own answer arrives
    paintLabel("Servers: …");
    if (change) change.hidden = !canAdministerCase(id);
    let res;
    let body;
    try {
      res = await fetch(`/cases/${encodeURIComponent(id)}/server-set`);
      body = await readJson(res);
    } catch (e) {
      res = { ok: false, status: 0 };
      body = { error: e.message };
    }
    if (current.caseId !== id) return; // the analyst moved on; this answer is for the old case
    if (res.ok) {
      current = { caseId: id, setId: body.setId || "", tools: Array.isArray(body.tools) ? body.tools : [] };
      paintLabel(`Servers: ${body.name || ""}`);
    } else {
      current = { caseId: id, setId: "", tools: [] };
      paintLabel("Servers: none", body.error || `HTTP ${res.status}`);
    }
    applyCaseTools();
  }

  // ── Change… ────────────────────────────────────────────────────────────────────────────────

  function setMsg(id, text) {
    const box = byId(id);
    if (box) box.textContent = text || "";
  }

  function closeOverlay(id) {
    const overlay = byId(id);
    if (overlay) overlay.classList.remove("open");
  }

  async function openPicker() {
    const select = byId("caseServersPick");
    setMsg("caseServersPickMsg", "");
    select.textContent = "";
    byId("caseServersPickOverlay").classList.add("open");
    try {
      const list = await fetchServerSets();
      for (const set of list.sets) {
        const opt = document.createElement("option");
        opt.value = set.id;
        opt.textContent = set.name;
        select.appendChild(opt);
      }
      select.value = current.setId || list.defaultId;
    } catch (e) {
      setMsg("caseServersPickMsg", `Server sets cannot be loaded: ${e.message}`);
    }
    select.focus();
  }

  function changeError(res, body) {
    if (res.status === 403) return "You do not have permission to change this case's server set.";
    return body.error || `The change did not finish (HTTP ${res.status}).`;
  }

  async function postChange(setId, confirmed) {
    const caseId = current.caseId;
    const res = await fetch(`/cases/${encodeURIComponent(caseId)}/server-set`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(confirmed ? { setId, confirm: true } : { setId }),
    });
    return { res, body: await readJson(res), caseId };
  }

  async function applyPicked() {
    const apply = byId("caseServersPickApply");
    const setId = byId("caseServersPick").value;
    if (!setId || setId === current.setId) return closeOverlay("caseServersPickOverlay");
    apply.disabled = true;
    setMsg("caseServersPickMsg", "Changing…");
    try {
      const { res, body, caseId } = await postChange(setId, false);
      if (res.status === 409 && body.needsConfirm) {
        closeOverlay("caseServersPickOverlay");
        openConfirm(setId, body.work || {});
      } else if (res.ok) {
        closeOverlay("caseServersPickOverlay");
        await refreshCaseServers(caseId);
      } else {
        setMsg("caseServersPickMsg", changeError(res, body));
      }
    } catch (e) {
      setMsg("caseServersPickMsg", `The change did not finish: ${e.message}`);
    } finally {
      apply.disabled = false;
    }
  }

  function workLines(work) {
    const lines = [];
    const monitors = Number(work.monitors) || 0;
    const hunts = Number(work.hunts) || 0;
    if (monitors > 0) lines.push(`${plural(monitors, "live monitor", "live monitors")} will stop.`);
    if (work.irisCase) lines.push(`The link to IRIS case '${work.irisCase}' will be forgotten.`);
    if (hunts > 0) lines.push(`${plural(hunts, "Velociraptor hunt", "Velociraptor hunts")} will be forgotten.`);
    return lines;
  }

  function openConfirm(setId, work) {
    pendingSetId = setId;
    byId("caseServersConfirmTitle").textContent = "Change server set?";
    const list = byId("caseServersConfirmList");
    list.textContent = "";
    for (const line of workLines(work)) {
      const li = document.createElement("li");
      li.textContent = line;
      list.appendChild(li);
    }
    byId("caseServersConfirmNote").textContent = NOTE;
    byId("caseServersConfirmBtn").textContent = "Change servers";
    byId("caseServersConfirmCancel").textContent = "Cancel";
    setMsg("caseServersConfirmMsg", "");
    byId("caseServersConfirmOverlay").classList.add("open");
    byId("caseServersConfirmCancel").focus(); // the safe choice has focus
  }

  function cancelConfirm() {
    pendingSetId = "";
    closeOverlay("caseServersConfirmOverlay");
  }

  async function confirmChange() {
    const btn = byId("caseServersConfirmBtn");
    if (!pendingSetId) return cancelConfirm();
    btn.disabled = true;
    setMsg("caseServersConfirmMsg", "Changing…");
    try {
      const { res, body, caseId } = await postChange(pendingSetId, true);
      if (!res.ok) {
        setMsg("caseServersConfirmMsg", changeError(res, body));
        return;
      }
      cancelConfirm();
      await refreshCaseServers(caseId);
    } catch (e) {
      setMsg("caseServersConfirmMsg", `The change did not finish: ${e.message}`);
    } finally {
      btn.disabled = false;
    }
  }

  function onEscape(close) {
    return (e) => {
      if (e.key === "Escape") close();
    };
  }

  function initCaseServers() {
    byId("caseServersChangeBtn").onclick = openPicker;
    byId("caseServersPickApply").onclick = applyPicked;
    byId("caseServersPickCancel").onclick = () => closeOverlay("caseServersPickOverlay");
    byId("caseServersConfirmBtn").onclick = confirmChange;
    byId("caseServersConfirmCancel").onclick = cancelConfirm;
    byId("caseServersPickOverlay").addEventListener(
      "keydown",
      onEscape(() => closeOverlay("caseServersPickOverlay")),
    );
    byId("caseServersConfirmOverlay").addEventListener("keydown", onEscape(cancelConfirm));
  }

  window.initCaseServers = initCaseServers;
  window.refreshCaseServers = refreshCaseServers;
  window.caseToolEnabled = caseToolEnabled;
  window.setDefaultServerTools = setDefaultServerTools;
})();
