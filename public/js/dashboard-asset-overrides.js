// Asset overrides (rename / add / suppress / link) — the per-case corrections an analyst applies to
// the asset inventory (#415 tier 3).
//
// THIS MODULE IS NOTHING BUT AN INITIALIZER, and that is what the block was. It declares no
// functions and no state: every one of its 111 lines is a listener bound at module scope, six
// statements' worth. Nothing outside the block calls into it, so it publishes only initAssetOverrides.
//
// Which makes the initializer the entire point. In a <head> script all six statements would query
// their elements before the markup exists and bind nothing at all — the whole feature, silently
// inert, with no error anywhere.
(function () {
  function initAssetOverrides() {
    // ── Asset overrides (rename / add / suppress / link) ───────────────────────────
    document.getElementById("addAssetBtn").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      const name = document.getElementById("assetAddName").value.trim();
      const type = document.getElementById("assetAddType").value;
      const msg = document.getElementById("addAssetMsg");
      if (!name) {
        msg.textContent = "name required";
        return;
      }
      msg.textContent = "…";
      fetch(`/cases/${encodeURIComponent(caseId)}/asset-overrides/assets`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name, type }),
      })
        .then((r) =>
          r.ok ? r.json() : r.json().then((e) => Promise.reject(e.error)),
        )
        .then(() => {
          msg.textContent = "added ✓";
          document.getElementById("assetAddName").value = "";
          setTimeout(() => (msg.textContent = ""), 2500);
          loadAssetGraph(caseId);
          loadAssetOverrides(caseId);
        })
        .catch((e) => {
          msg.textContent =
            "failed: " + e + " — restart the companion server if this 404s";
        });
    };
    document.getElementById("addLinkBtn").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      const asset = document.getElementById("assetLinkAsset").value.trim();
      const ioc = document.getElementById("assetLinkIoc").value.trim();
      const msg = document.getElementById("addLinkMsg");
      if (!asset || !ioc) {
        msg.textContent = "asset id and IoC id are required";
        return;
      }
      msg.textContent = "…";
      fetch(`/cases/${encodeURIComponent(caseId)}/asset-overrides/links`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ asset, ioc }),
      })
        .then((r) =>
          r.ok ? r.json() : r.json().then((e) => Promise.reject(e.error)),
        )
        .then(() => {
          msg.textContent = "linked ✓";
          setTimeout(() => (msg.textContent = ""), 2500);
          loadAssetGraph(caseId);
          loadAssetOverrides(caseId);
        })
        .catch((e) => {
          msg.textContent =
            "failed: " + e + " — restart the companion server if this 404s";
        });
    };
    document.getElementById("delLinkBtn").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      const asset = document.getElementById("assetLinkAsset").value.trim();
      const ioc = document.getElementById("assetLinkIoc").value.trim();
      const msg = document.getElementById("addLinkMsg");
      if (!asset || !ioc) {
        msg.textContent = "asset id and IoC id are required";
        return;
      }
      msg.textContent = "…";
      fetch(
        `/cases/${encodeURIComponent(caseId)}/asset-overrides/links?asset=${encodeURIComponent(asset)}&ioc=${encodeURIComponent(ioc)}`,
        { method: "DELETE" },
      )
        .then((r) =>
          r.ok ? r.json() : r.json().then((e) => Promise.reject(e.error)),
        )
        .then(() => {
          msg.textContent = "unlinked ✓";
          setTimeout(() => (msg.textContent = ""), 2500);
          loadAssetGraph(caseId);
          loadAssetOverrides(caseId);
        })
        .catch((e) => {
          msg.textContent =
            "failed: " + e + " — restart the companion server if this 404s";
        });
    };
    // Rename / suppress / restore buttons inside the asset list (event delegation).
    document.getElementById("assetList").addEventListener("click", (e) => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      const renameBtn = e.target.closest(".asset-rename-btn");
      const mergeBtn = e.target.closest(".asset-merge-btn");
      const unmergeBtn = e.target.closest(".asset-unmerge-btn");
      const delBtn = e.target.closest(".asset-del-btn");
      const restoreBtn = e.target.closest(".asset-restore-btn");
      if (renameBtn) {
        const id = renameBtn.dataset.assetid;
        const cur = renameBtn.dataset.name;
        const newName = prompt(
          `Rename "${cur}" to (leave empty to clear rename):`,
          cur,
        );
        if (newName === null) return;
        fetch(
          `/cases/${encodeURIComponent(caseId)}/asset-overrides/assets/${encodeURIComponent(id)}`,
          {
            method: "PUT",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ name: newName }),
          },
        )
          .then(() => {
            loadAssetGraph(caseId);
            loadAssetOverrides(caseId);
          })
          .catch(() => {});
      } else if (mergeBtn) {
        const id = mergeBtn.dataset.assetid;
        const cur = mergeBtn.dataset.name;
        const type = mergeBtn.dataset.assettype;
        // Asked of the graph rather than reaching into its payload (#415).
        const candidates = (
          typeof assetGraphAssets === "function" ? assetGraphAssets() : []
        )
          .filter((a) => a.id !== id && a.type === type)
          .map((a) => ({ id: a.id, label: a.name }));
        openMergeModal(
          `Merge "${cur}" into which ${type}?`,
          candidates,
          (into) =>
            fetch(
              `/cases/${encodeURIComponent(caseId)}/asset-overrides/assets/${encodeURIComponent(id)}/merge`,
              {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ into }),
              },
            )
              .then((r) =>
                r.ok ? null : r.json().then((e) => Promise.reject(e.error)),
              )
              .then(() => {
                loadAssetGraph(caseId);
                loadAssetOverrides(caseId);
              }),
        );
      } else if (unmergeBtn) {
        const id = unmergeBtn.dataset.assetid;
        fetch(
          `/cases/${encodeURIComponent(caseId)}/asset-overrides/assets/${encodeURIComponent(id)}/unmerge`,
          { method: "POST" },
        )
          .then(() => {
            loadAssetGraph(caseId);
            loadAssetOverrides(caseId);
          })
          .catch(() => {});
      } else if (delBtn) {
        const id = delBtn.dataset.assetid;
        fetch(
          `/cases/${encodeURIComponent(caseId)}/asset-overrides/assets/${encodeURIComponent(id)}`,
          { method: "DELETE" },
        )
          .then(() => {
            loadAssetGraph(caseId);
            loadAssetOverrides(caseId);
          })
          .catch(() => {});
      } else if (restoreBtn) {
        const id = restoreBtn.dataset.assetid;
        fetch(
          `/cases/${encodeURIComponent(caseId)}/asset-overrides/assets/${encodeURIComponent(id)}/restore`,
          { method: "POST" },
        )
          .then(() => {
            loadAssetGraph(caseId);
            loadAssetOverrides(caseId);
          })
          .catch(() => {});
      }
    });

    // The (+) next to a section heading toggles that section's manual add-entry form. We stop the
    // click from bubbling to the h2 (which would collapse the section), and expand the section if
    // it was collapsed so the form is visible.
    document.querySelectorAll(".add-toggle").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const sec = btn.closest("section");
        const wrap = sec && sec.querySelector(".manual-add");
        if (!wrap) return;
        const show = wrap.hasAttribute("hidden");
        if (show) {
          wrap.removeAttribute("hidden");
          sec.classList.remove("collapsed");
          const first = wrap.querySelector("input, select");
          if (first) first.focus();
        } else {
          wrap.setAttribute("hidden", "");
        }
        btn.classList.toggle("active", show);
      });
    });
  }

  window.initAssetOverrides = initAssetOverrides;
})();
