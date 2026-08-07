// Custom importers (declarative external plugin layer) (#415 tier 3).
//
// wlApplyToCase DID NOT COME WITH IT. That is the IOC whitelist's "apply to this case" action; it
// sat in this block only by position, and the whitelist extraction deliberately left its BUTTON
// wired in the page because the function was down here. Both halves are reunited now — the
// function moved into js/dashboard-ioc-whitelist.js and its binding with it.
(function () {
  // --- Custom importers (declarative external plugin layer) — global, Settings → Importers -------
  function renderImporters(d) {
    const list = document.getElementById("impList");
    const status = document.getElementById("impStatus");
    const cnt = document.getElementById("impCount");
    const errBox = document.getElementById("impErrors");
    const errCnt = document.getElementById("impErrCount");
    const importers = (d && d.importers) || [];
    const errors = (d && d.errors) || [];
    const prec = document.getElementById("impPrecedence");
    if (prec && d && d.precedence) prec.value = d.precedence;
    if (cnt) cnt.textContent = importers.length ? `(${importers.length})` : "";
    if (status)
      status.textContent = importers.length
        ? `${importers.length} custom importer${importers.length !== 1 ? "s" : ""} loaded — applied on every matching import.`
        : "No custom importers loaded — paste a definition below or drop one in the importers/ folder.";
    if (list) {
      list.innerHTML = importers.length
        ? importers
            .map(
              (m) =>
                `<div data-safe-style="display:flex;align-items:center;gap:6px;padding:2px 0;border-bottom:1px solid var(--border-subtle);font-size:12px">` +
                `<span data-safe-style="flex:1;word-break:break-all"><b>${esc(m.label)}</b> <code data-safe-style="color:var(--text-muted)">${esc(m.id)}</code></span>` +
                `<span data-safe-style="flex:0 0 auto;color:var(--text-dim)">priority ${esc(m.priority)}</span>` +
                `<button class="imp-del" data-id="${escAttr(m.id)}" title="Delete importer" data-safe-style="background:transparent;border:1px solid var(--danger-border);color:var(--tag-red-text);border-radius:5px;padding:0 7px;cursor:pointer">✕</button>` +
                `</div>`,
            )
            .join("")
        : "";
    }
    if (errCnt) errCnt.textContent = errors.length ? `(${errors.length})` : "";
    if (errBox) {
      errBox.innerHTML = errors.length
        ? errors
            .map(
              (e) =>
                `<div data-safe-style="padding:2px 0">⚠ <code>${esc(e.file)}</code>: ${esc((e.errors || []).map((x) => x.path + " — " + x.message).join("; "))}</div>`,
            )
            .join("")
        : "";
    }
  }
  function loadImporters() {
    const status = document.getElementById("impStatus");
    fetch("/importers")
      .then((r) => {
        if (!r.ok)
          throw new Error(r.status === 404 ? "404" : "HTTP " + r.status);
        return r.json();
      })
      .then(renderImporters)
      .catch((e) => {
        if (status)
          status.textContent =
            e.message === "404"
              ? "Restart the companion server — /importers 404 (server is stale)."
              : "Could not load importers: " + e.message;
      });
  }
  function impAdd() {
    const box = document.getElementById("impPasteBox");
    const msg = document.getElementById("impMsg");
    let spec;
    try {
      spec = JSON.parse(box.value);
    } catch (e) {
      msg.textContent = "Not valid JSON: " + e.message;
      return;
    }
    msg.textContent = "adding…";
    fetch("/importers", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ spec }),
    })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}));
        if (r.ok) {
          msg.textContent = "Added " + (j.id || "importer");
          box.value = "";
          loadImporters();
        } else if (r.status === 404) {
          msg.textContent =
            "Restart the companion server — /importers 404 (server is stale).";
        } else {
          msg.textContent =
            "Invalid: " +
            ((j.errors || [])
              .map((x) => x.path + " — " + x.message)
              .join("; ") ||
              j.error ||
              "HTTP " + r.status);
        }
      })
      .catch((e) => {
        msg.textContent = "failed: " + e.message;
      });
  }
  function impReload() {
    const msg = document.getElementById("impMsg");
    msg.textContent = "reloading…";
    fetch("/importers/reload", { method: "POST" })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            r.status === 404
              ? "Restart the companion server — /importers 404."
              : "HTTP " + r.status,
          );
        return r.json();
      })
      .then((d) => {
        msg.textContent = "reloaded";
        renderImporters(d);
        loadImporters();
      })
      .catch((e) => {
        msg.textContent = e.message;
      });
  }
  function impSetPrecedence(e) {
    const msg = document.getElementById("impMsg");
    const precedence = e.target.value;
    fetch("/importers/precedence", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ precedence }),
    })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then(() => {
        msg.textContent = `precedence set to ${precedence}`;
      })
      .catch((err) => {
        msg.textContent =
          "failed: " +
          err.message +
          " — restart the server if the endpoint 404s.";
      });
  }
  function impCopyPrompt() {
    const msg = document.getElementById("impMsg");
    fetch("/importers/prompt")
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            r.status === 404
              ? "Restart the companion server — /importers 404."
              : "HTTP " + r.status,
          );
        return r.json();
      })
      .then((j) =>
        navigator.clipboard.writeText(j.prompt || "").then(
          () => {
            msg.textContent =
              "LLM prompt copied — paste it + your file sample into any LLM.";
          },
          () => {
            msg.textContent =
              "Could not copy to clipboard — check browser permissions.";
          },
        ),
      )
      .catch((e) => {
        msg.textContent = e.message;
      });
  }

  // NSRL known-good hashes (#63) moved to js/dashboard-nsrl.js (#415 tier 3). Its nine controls
  // are bound by initNsrl(), called from the Settings block above.

  // Settings → Tools, MCP servers and the update check (#127) moved to
  // js/dashboard-settings-tools.js (#415 tier 3). Three panels, one Settings screen; the banner
  // here named only the last of them.

  // The five controls the page's Settings block bound at module scope.
  function initCustomImporters() {
    // Custom importers (declarative external plugin layer)
    document.getElementById("impAddBtn").addEventListener("click", impAdd);
    document
      .getElementById("impReloadBtn")
      .addEventListener("click", impReload);
    document
      .getElementById("impPromptBtn")
      .addEventListener("click", impCopyPrompt);
    document
      .getElementById("impPrecedence")
      .addEventListener("change", impSetPrecedence);
    document.getElementById("impList").addEventListener("click", (e) => {
      const del = e.target.closest(".imp-del");
      if (del) {
        fetch("/importers/" + encodeURIComponent(del.dataset.id), {
          method: "DELETE",
        })
          .then((r) => {
            if (r.ok) loadImporters();
          })
          .catch(() => {});
      }
    });
  }
  window.initCustomImporters = initCustomImporters;
  window.loadImporters = loadImporters;
  window.impAdd = impAdd;
  window.impReload = impReload;
  window.impSetPrecedence = impSetPrecedence;
  window.impCopyPrompt = impCopyPrompt;
})();
