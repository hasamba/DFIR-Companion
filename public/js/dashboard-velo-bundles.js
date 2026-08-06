// Velociraptor triage bundles — building named bundles of CLIENT artifacts and running one as a
// hunt (#415 tier 3).
//
// The other half of the CLIENT_EVENT banner. Its wiring was a self-calling
// `(function wireVeloTriage(){…})()` — the eighth in this PR — which in a <head> script runs before
// the builder's controls exist and binds nothing.
(function () {
  // The builder's artifact selection. Declared in the inline block until #415 tier 3, but THIRTEEN
  // of its uses are here and two of them are assignments — the page only reset it once. Ownership
  // follows use, so it lives here and js/dashboard-velo-triage.js calls resetVeloSelected().
  let veloSelected = new Set();

  function veloBrowseArtifacts() {
    const picker = document.getElementById("veloArtifactPicker");
    const btn = document.getElementById("veloBrowseBtn");
    picker.textContent = "loading artifacts…";
    if (btn) btn.disabled = true;
    // refresh=1: a deliberate Browse bypasses the server-side catalog cache, so an artifact just
    // added on the Velociraptor server shows up immediately instead of after the cache TTL.
    fetch("/velociraptor/artifacts?refresh=1")
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          picker.innerHTML = `<span data-safe-style="color:var(--sev-high)">error: ${esc(j.error || "failed")}</span>`;
          return;
        }
        veloArtifactCache = j.artifacts || [];
        renderVeloPicker();
      })
      .catch(
        (e) =>
          (picker.innerHTML = `<span data-safe-style="color:var(--sev-high)">error: ${esc(e.message)} — restart the companion server if this 404s</span>`),
      )
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }
  function renderVeloPicker() {
    const picker = document.getElementById("veloArtifactPicker");
    if (!picker) return;
    if (!veloArtifactCache.length) {
      picker.innerHTML =
        "<span>no artifacts loaded — click Browse server artifacts</span>";
      return;
    }
    const filter = (
      document.getElementById("veloArtifactSearch").value || ""
    ).toLowerCase();
    const list = veloArtifactCache.filter(
      (a) =>
        !filter ||
        a.name.toLowerCase().includes(filter) ||
        (a.description || "").toLowerCase().includes(filter),
    );
    const groups = {};
    for (const a of list) {
      const g = a.name.split(".")[0] || "Other";
      (groups[g] = groups[g] || []).push(a);
    }
    const keys = Object.keys(groups).sort();
    picker.innerHTML =
      keys
        .map((g) => {
          const items = groups[g]
            .map((a) => {
              const checked = veloSelected.has(a.name) ? "checked" : "";
              return `<label data-safe-style="display:block;color:var(--text-primary);margin:2px 0" title="${escAttr(a.description || "")}"><input type="checkbox" class="velo-art-cb" value="${escAttr(a.name)}" ${checked}> ${esc(a.name)}</label>`;
            })
            .join("");
          return `<div data-safe-style="margin-bottom:6px"><div data-safe-style="color:var(--accent);font-weight:600;margin:4px 0">${esc(g)} <span data-safe-style="color:var(--text-dim);font-weight:400">(${groups[g].length})</span></div>${items}</div>`;
        })
        .join("") || "<span>no matches</span>";
    picker.querySelectorAll(".velo-art-cb").forEach(
      (cb) =>
        (cb.onchange = () => {
          if (cb.checked) veloSelected.add(cb.value);
          else veloSelected.delete(cb.value);
          renderVeloSelected();
        }),
    );
  }
  function renderVeloSelected() {
    const cnt = document.getElementById("veloSelectedCount");
    const list = document.getElementById("veloSelectedList");
    if (cnt) cnt.textContent = veloSelected.size;
    if (!list) return;
    list.innerHTML = [...veloSelected]
      .map(
        (n) =>
          `<span data-safe-style="background:var(--bg-drop-active);border:1px solid var(--border-color);border-radius:4px;padding:2px 6px;font-size:11px;color:var(--text-primary)">${esc(n)} <a href="#" class="velo-sel-rm" data-n="${escAttr(n)}" data-safe-style="color:var(--tag-red-text);text-decoration:none">✕</a></span>`,
      )
      .join("");
    list.querySelectorAll(".velo-sel-rm").forEach(
      (a) =>
        (a.onclick = (e) => {
          e.preventDefault();
          veloSelected.delete(a.dataset.n);
          renderVeloSelected();
          const cbs = document.querySelectorAll(".velo-art-cb");
          for (const cb of cbs)
            if (cb.value === a.dataset.n) cb.checked = false;
        }),
    );
  }
  function veloAddManual() {
    const inp = document.getElementById("veloArtifactManual");
    const name = (inp.value || "").trim();
    if (!name) return;
    veloSelected.add(name);
    inp.value = "";
    renderVeloSelected();
  }
  function veloSaveBundle() {
    const name = (document.getElementById("veloBundleName").value || "").trim();
    const description = (
      document.getElementById("veloBundleDesc").value || ""
    ).trim();
    const defaultWaitMinutes =
      Number(document.getElementById("veloBundleDefaultWait").value) ||
      undefined;
    const timeoutSeconds =
      Number(document.getElementById("veloBundleTimeout").value) || undefined;
    const expirySeconds =
      Number(document.getElementById("veloBundleExpiry").value) || undefined;
    const msg = document.getElementById("veloBuilderMsg");
    if (!name) {
      msg.textContent = "name is required";
      return;
    }
    if (!veloSelected.size) {
      msg.textContent = "select at least one artifact";
      return;
    }
    const paramsRaw = (
      document.getElementById("veloBundleParams").value || ""
    ).trim();
    let params;
    if (paramsRaw) {
      try {
        params = JSON.parse(paramsRaw);
      } catch {
        msg.textContent = "Advanced parameters must be valid JSON";
        return;
      }
    }
    const filtersRaw = (
      document.getElementById("veloBundleFilters").value || ""
    ).trim();
    let filters;
    if (filtersRaw) {
      try {
        filters = JSON.parse(filtersRaw);
      } catch {
        msg.textContent = "Advanced exclude filters must be valid JSON";
        return;
      }
    }
    const btn = document.getElementById("veloSaveBundleBtn");
    const wasEditing = !!veloEditingId;
    const body = {
      name,
      description,
      artifacts: [...veloSelected],
      defaultWaitMinutes,
      timeoutSeconds,
      expirySeconds,
      params,
      filters,
    };
    if (veloEditingId) body.id = veloEditingId; // editing a built-in or custom bundle overrides it in place
    btn.disabled = true;
    msg.textContent = wasEditing ? "updating…" : "saving…";
    fetch("/bundles", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          msg.textContent = "error: " + (j.error || "failed");
          return;
        }
        veloClearBuilder(); // resets fields + editing state (leaves msg alone)
        loadVeloBundles();
        msg.textContent = wasEditing ? "updated ✓" : "saved ✓";
        setTimeout(() => {
          msg.textContent = "";
        }, 1500);
      })
      .catch(
        (e) =>
          (msg.textContent =
            "error: " +
            e.message +
            " — restart the companion server if this 404s"),
      )
      .finally(() => {
        btn.disabled = false;
      });
  }
  // Load a bundle's fields into the builder (shared by Edit + Duplicate).
  function veloApplyToBuilder(b) {
    document.getElementById("veloBundleName").value = b.name || "";
    document.getElementById("veloBundleDesc").value = b.description || "";
    document.getElementById("veloBundleDefaultWait").value =
      b.defaultWaitMinutes || "";
    document.getElementById("veloBundleTimeout").value = b.timeoutSeconds || "";
    document.getElementById("veloBundleExpiry").value = String(
      b.expirySeconds || 3600,
    ); // default 1 hour
    document.getElementById("veloBundleParams").value =
      b.params && Object.keys(b.params).length
        ? JSON.stringify(b.params, null, 2)
        : "";
    document.getElementById("veloBundleFilters").value =
      b.filters && Object.keys(b.filters).length
        ? JSON.stringify(b.filters, null, 2)
        : "";
    veloSelected = new Set(b.artifacts || []);
    renderVeloSelected();
    renderVeloPicker();
    const builder = document.getElementById("veloBuilder");
    if (builder) builder.open = true;
    document
      .getElementById("veloBundleName")
      .scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
  // Reflect whether the builder is creating a new bundle or editing an existing one.
  function veloSetEditing(id, name) {
    veloEditingId = id || null;
    const save = document.getElementById("veloSaveBundleBtn");
    const sum = document.getElementById("veloBuilderSummary");
    const neu = document.getElementById("veloNewBundleBtn");
    if (save)
      save.textContent = veloEditingId ? "Update bundle" : "Save bundle";
    if (sum)
      sum.textContent = veloEditingId
        ? `Editing: ${name || veloEditingId}`
        : "Build a new bundle";
    if (neu) neu.style.display = veloEditingId ? "" : "none";
  }
  function veloClearBuilder() {
    document.getElementById("veloBundleName").value = "";
    document.getElementById("veloBundleDesc").value = "";
    document.getElementById("veloBundleDefaultWait").value = "";
    document.getElementById("veloBundleTimeout").value = "";
    document.getElementById("veloBundleExpiry").value = "3600"; // back to the 1-hour default
    document.getElementById("veloBundleParams").value = "";
    document.getElementById("veloBundleFilters").value = "";
    veloSelected = new Set();
    renderVeloSelected();
    renderVeloPicker();
    veloSetEditing(null);
  }
  function veloEdit(id) {
    const b = (veloBundlesList() || []).find((x) => x.id === id);
    if (!b) return;
    veloApplyToBuilder(b);
    veloSetEditing(b.id, b.name);
    const msg = document.getElementById("veloBuilderMsg");
    if (msg) msg.textContent = "";
  }
  function veloDuplicate(id) {
    const b = (veloBundlesList() || []).find((x) => x.id === id);
    if (!b) return;
    veloApplyToBuilder({ ...b, name: b.name + " (copy)" });
    veloSetEditing(null); // a duplicate is saved as a NEW bundle
    const msg = document.getElementById("veloBuilderMsg");
    if (msg) msg.textContent = "";
  }
  function veloDeleteBundle(id) {
    if (!confirm("Delete this bundle?")) return;
    fetch("/bundles/" + encodeURIComponent(id), { method: "DELETE" })
      .then((r) => {
        if (r.ok || r.status === 204) return;
        return r.json().then((j) => {
          throw new Error(j.error || "HTTP " + r.status);
        });
      })
      .then(() => loadVeloBundles())
      .catch((e) => {
        const msg = document.getElementById("veloBuilderMsg");
        if (msg) msg.textContent = "delete failed: " + e.message;
      });
  }
  function veloResetBuiltin(id) {
    if (
      !confirm(
        "Discard your edits to this built-in bundle and restore the shipped default?",
      )
    )
      return;
    fetch("/bundles/" + encodeURIComponent(id), { method: "DELETE" })
      .then((r) => {
        if (r.ok || r.status === 204) return;
        return r.json().then((j) => {
          throw new Error(j.error || "HTTP " + r.status);
        });
      })
      .then(() => loadVeloBundles())
      .catch((e) => {
        const msg = document.getElementById("veloBuilderMsg");
        if (msg) msg.textContent = "reset failed: " + e.message;
      });
  }

  function initVeloBundles() {
    // One-time wiring for the static builder controls (the script runs after the DOM is parsed).
    (function wireVeloTriage() {
      const browse = document.getElementById("veloBrowseBtn");
      if (browse) browse.onclick = veloBrowseArtifacts;
      const refreshClients = document.getElementById("veloRefreshClientsBtn");
      if (refreshClients) refreshClients.onclick = doRefreshVeloClients;
      const reconnect = document.getElementById("veloReconnectBtn");
      if (reconnect) reconnect.onclick = doVeloReconnect;
      const addM = document.getElementById("veloAddManualBtn");
      if (addM) addM.onclick = veloAddManual;
      const save = document.getElementById("veloSaveBundleBtn");
      if (save) save.onclick = veloSaveBundle;
      const neu = document.getElementById("veloNewBundleBtn");
      if (neu)
        neu.onclick = () => {
          veloClearBuilder();
          const m = document.getElementById("veloBuilderMsg");
          if (m) m.textContent = "";
        };
      const search = document.getElementById("veloArtifactSearch");
      if (search) search.oninput = renderVeloPicker;
      const manual = document.getElementById("veloArtifactManual");
      if (manual)
        manual.onkeydown = (e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            veloAddManual();
          }
        };
      const extGo = document.getElementById("veloExtGo");
      if (extGo) extGo.onclick = veloImportExternal;
      loadVeloBundles(); // populate the bundle list even before a case is connected
    })();
  }

  window.renderVeloSelected = renderVeloSelected;
  window.veloClearBuilder = veloClearBuilder;
  window.veloEdit = veloEdit;
  window.veloDuplicate = veloDuplicate;
  window.veloDeleteBundle = veloDeleteBundle;
  window.veloResetBuiltin = veloResetBuiltin;
  function resetVeloSelected() {
    veloSelected = new Set();
  }

  window.resetVeloSelected = resetVeloSelected;
  window.initVeloBundles = initVeloBundles;
})();
