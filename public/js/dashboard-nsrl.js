// NSRL known-good hashes (#63) — the global allow-list of vendor-shipped file hashes, and applying
// it to a case so known-good files stop being reported as findings (#415 tier 3).
//
// IIFE-WRAPPED AS A MATTER OF COURSE: it owns no top-level binding today, but this is a CLASSIC
// script, so anything added at this level later would join the shared global lexical environment.
//
// ITS WIRING IS AN INITIALIZER. Nine controls were bound in the page's Settings block, six of them
// passing one of these functions as a VALUE — `addEventListener("click", nsrlImport)` — so with the
// functions moved out a 404 here would throw while the page parses rather than leaving one panel
// inert.
(function () {
  // --- NSRL known-good hashes (#63) — global hash set, Settings → NSRL ---------------------------
  function loadNsrl() {
    const status = document.getElementById("nsrlStatus");
    const cnt = document.getElementById("nsrlCount");
    fetch("/nsrl")
      .then((r) => r.json())
      .then((j) => {
        const n = j.count || 0;
        if (cnt) cnt.textContent = n ? `(${n.toLocaleString()})` : "";
        if (status)
          status.textContent = n
            ? `${n.toLocaleString()} known-good hash${n !== 1 ? "es" : ""} loaded — matches auto-marked as a false positive on import.`
            : "No hashes loaded yet — import an NSRL set below to start filtering known-good files.";
        renderNsrlDb(j);
      })
      .catch(() => {
        if (status)
          status.textContent =
            "could not load — restart the server if this persists.";
      });
  }
  function renderNsrlDb(j) {
    const st = document.getElementById("nsrlDbStatus");
    const badge = document.getElementById("nsrlDbBadge");
    const controls = document.getElementById("nsrlDbControls");
    const disc = document.getElementById("nsrlDbDisconnectBtn");
    const db = (j && j.db) || { connected: false };
    if (db.connected) {
      if (badge) badge.textContent = "● connected";
      if (badge) badge.style.color = "#7ee787";
      if (st)
        st.innerHTML = `Querying <code>${esc(db.path || "")}</code> — table <strong>${esc(db.table || "?")}</strong>, columns ${esc((db.columns || []).join(", ") || "?")}.`;
    } else {
      if (badge) {
        badge.textContent = "";
      }
      if (st)
        st.textContent =
          "Not connected — for the full RDS, connect the SQLite .db below.";
    }
    // Env-managed: the path comes from DFIR_NSRL_DB; hide the runtime connect controls.
    const envManaged = j && j.dbEnvManaged;
    if (controls) controls.style.display = envManaged ? "none" : "flex";
    if (envManaged && st)
      st.innerHTML += ` <span data-safe-style="color:#7e8aa0">(path set by <code>DFIR_NSRL_DB</code>)</span>`;
    if (disc) disc.style.display = db.connected ? "" : "none";
  }
  function nsrlDbConnect() {
    const path = document.getElementById("nsrlDbPath").value.trim();
    const msg = document.getElementById("nsrlDbMsg");
    if (!path) {
      msg.textContent = "enter the RDS .db file path";
      return;
    }
    msg.textContent = "connecting…";
    fetch("/nsrl/db", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ path }),
    })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
        return j;
      })
      .then((j) => {
        msg.textContent = `connected (table ${j.table}, ${(j.columns || []).join("/")})`;
        document.getElementById("nsrlDbPath").value = "";
        loadNsrl();
      })
      .catch((e) => {
        msg.textContent = e.message;
      });
  }
  function nsrlDbDisconnect() {
    const msg = document.getElementById("nsrlDbMsg");
    msg.textContent = "disconnecting…";
    fetch("/nsrl/db", { method: "DELETE" })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
        return j;
      })
      .then(() => {
        msg.textContent = "disconnected";
        loadNsrl();
      })
      .catch((e) => {
        msg.textContent = e.message;
      });
  }
  function nsrlImport() {
    const text = document.getElementById("nsrlImportText").value;
    const msg = document.getElementById("nsrlMsg");
    if (!text.trim()) {
      msg.textContent = "paste an NSRL file or hash list first";
      return;
    }
    msg.textContent = "importing…";
    fetch("/nsrl/import", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
    })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then((j) => {
        msg.textContent = `imported ${j.added.toLocaleString()} new hash${j.added !== 1 ? "es" : ""} (${j.parsed.toLocaleString()} parsed, ${j.total.toLocaleString()} total)`;
        document.getElementById("nsrlImportText").value = "";
        loadNsrl();
      })
      .catch((e) => {
        msg.textContent = e.message;
      });
  }
  function nsrlImportFile() {
    const path = document.getElementById("nsrlFilePath").value.trim();
    const msg = document.getElementById("nsrlFileMsg");
    if (!path) {
      msg.textContent = "enter a file path on the server";
      return;
    }
    msg.textContent = "loading…";
    fetch("/nsrl/import-file", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ path }),
    })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
        return j;
      })
      .then((j) => {
        const errs = (j.files || []).filter((f) => f.error);
        msg.textContent =
          `loaded ${(j.added || 0).toLocaleString()} new hash${j.added !== 1 ? "es" : ""} (${(j.total || 0).toLocaleString()} total)` +
          (errs.length
            ? ` · ${errs.length} file(s) failed: ${esc(errs.map((f) => f.error).join("; "))}`
            : "");
        if (!errs.length) document.getElementById("nsrlFilePath").value = "";
        loadNsrl();
      })
      .catch((e) => {
        msg.textContent =
          e.message + " — restart the server if the endpoint 404s.";
      });
  }
  function nsrlClear() {
    if (
      !confirm(
        "Clear the entire NSRL known-good hash set? This is global (affects all cases).",
      )
    )
      return;
    const msg = document.getElementById("nsrlMsg");
    msg.textContent = "clearing…";
    fetch("/nsrl/clear", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then(() => {
        msg.textContent = "cleared";
        loadNsrl();
      })
      .catch((e) => {
        msg.textContent = e.message;
      });
  }
  function nsrlApplyToCase() {
    const caseId = document.getElementById("caseId").value.trim();
    const msg = document.getElementById("nsrlApplyMsg");
    if (!caseId) {
      msg.textContent = "load a case first";
      return;
    }
    msg.textContent = "applying…";
    fetch(`/cases/${caseId}/nsrl/apply`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then((j) => {
        msg.textContent = `${j.matchedIocs} IOC(s) + ${j.matchedEvents} event(s) matched · ${j.added} newly marked false positive`;
        if (j.legitimate) renderFalsePositives(j.legitimate);
      })
      .catch((e) => {
        msg.textContent =
          "failed: " +
          e.message +
          " — restart the server if the endpoint 404s.";
      });
  }

  // The nine controls the Settings block used to bind. Order unchanged.
  function initNsrl() {
    document
      .getElementById("nsrlImportBtn")
      .addEventListener("click", nsrlImport);
    document
      .getElementById("nsrlFileBtn")
      .addEventListener("click", nsrlImportFile);
    document.getElementById("nsrlFilePath").addEventListener("keydown", (e) => {
      if (e.key === "Enter") nsrlImportFile();
    });
    document
      .getElementById("nsrlExportBtn")
      .addEventListener("click", () => window.open("/nsrl/export", "_blank"));
    document
      .getElementById("nsrlClearBtn")
      .addEventListener("click", nsrlClear);
    document
      .getElementById("nsrlApplyBtn")
      .addEventListener("click", nsrlApplyToCase);
    document
      .getElementById("nsrlDbConnectBtn")
      .addEventListener("click", nsrlDbConnect);
    document
      .getElementById("nsrlDbDisconnectBtn")
      .addEventListener("click", nsrlDbDisconnect);
    document.getElementById("nsrlDbPath").addEventListener("keydown", (e) => {
      if (e.key === "Enter") nsrlDbConnect();
    });
  }

  window.loadNsrl = loadNsrl;
  window.nsrlImport = nsrlImport;
  window.nsrlImportFile = nsrlImportFile;
  window.nsrlClear = nsrlClear;
  window.nsrlApplyToCase = nsrlApplyToCase;
  window.nsrlDbConnect = nsrlDbConnect;
  window.nsrlDbDisconnect = nsrlDbDisconnect;
  window.initNsrl = initNsrl;
})();
