// Settings "Browse…" file picker for the Velociraptor API config / binary path fields, plus the
// "Download latest release" button next to the binary path field.
//
// This is a plain Express web app with no native OS file-open dialog, so the browse button drives
// a simple in-page directory browser (fsBrowseOverlay in dashboard.html) against the server-side
// GET /settings/browse-fs listing endpoint instead. Deliberately independent of the generic
// openMergeModal (dashboard-merge-picker.js): that modal always closes after its onConfirm
// resolves, which doesn't fit "drill into a folder, keep the modal open."
(function () {
  let state = null; // { dir, entries, parent, selected, targetInputId }

  // esc() is the page-wide helper from js/dashboard-escape.js (loaded before this module).

  function renderEntries() {
    const term = document
      .getElementById("fsBrowseSearch")
      .value.trim()
      .toLowerCase();
    const rows = [];
    if (state.parent)
      rows.push({ id: state.parent, label: ".. (up)", isDir: true });
    for (const e of state.entries) {
      if (term && !e.name.toLowerCase().includes(term)) continue;
      rows.push({
        id: e.path,
        label: (e.isDir ? "📁 " : "📄 ") + e.name,
        isDir: e.isDir,
      });
    }
    const el = document.getElementById("fsBrowseEntries");
    if (!rows.length) {
      el.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px;padding:4px'>No entries.</div>";
      return;
    }
    el.innerHTML = rows
      .map((r) => {
        const selected = !r.isDir && r.id === state.selected;
        const border = selected ? "var(--sev-low)" : "var(--border-color)";
        const bg = selected ? "rgba(107,203,119,0.12)" : "transparent";
        return `<div class="merge-candidate-row" data-id="${esc(r.id)}" data-isdir="${r.isDir ? "1" : ""}" data-safe-style="cursor:pointer;padding:5px 8px;border-radius:6px;border:1px solid ${border};background:${bg}">${esc(r.label)}</div>`;
      })
      .join("");
  }

  async function loadDir(dir) {
    const msg = document.getElementById("fsBrowseMsg");
    msg.textContent = "loading…";
    try {
      const resp = await fetch(
        "/settings/browse-fs?dir=" + encodeURIComponent(dir || ""),
      );
      const j = await resp.json();
      if (!resp.ok) throw new Error(j.error || "HTTP " + resp.status);
      state.dir = j.dir;
      state.parent = j.parent;
      state.entries = j.entries;
      state.selected = null;
      document.getElementById("fsBrowseSelectBtn").disabled = true;
      document.getElementById("fsBrowsePath").textContent = j.dir;
      msg.textContent = "";
      renderEntries();
    } catch (err) {
      msg.textContent = "failed: " + err.message;
    }
  }

  function openFsBrowseModal(title, startPath, targetInputId) {
    state = {
      dir: startPath,
      entries: [],
      parent: null,
      selected: null,
      targetInputId,
    };
    document.getElementById("fsBrowseTitle").textContent = title;
    document.getElementById("fsBrowseSearch").value = "";
    document.getElementById("fsBrowseOverlay").classList.add("open");
    loadDir(startPath);
  }

  function closeFsBrowseModal() {
    state = null;
    document.getElementById("fsBrowseOverlay").classList.remove("open");
  }

  function initFsBrowse() {
    document.getElementById("fsBrowseSearch").addEventListener("input", () => {
      if (state) renderEntries();
    });
    document
      .getElementById("fsBrowseEntries")
      .addEventListener("click", (e) => {
        const row = e.target.closest(".merge-candidate-row");
        if (!row || !state) return;
        if (row.dataset.isdir) {
          loadDir(row.dataset.id);
        } else {
          state.selected = row.dataset.id;
          document.getElementById("fsBrowseSelectBtn").disabled = false;
          renderEntries();
        }
      });
    document.getElementById("fsBrowseCancelBtn").onclick = closeFsBrowseModal;
    document.getElementById("fsBrowseSelectBtn").onclick = () => {
      if (!state || !state.selected) return;
      document.getElementById(state.targetInputId).value = state.selected;
      closeFsBrowseModal();
    };

    const apiConfigInput = document.getElementById(
      "env-DFIR_VELOCIRAPTOR_API_CONFIG",
    );
    const binaryInput = document.getElementById("env-DFIR_VELOCIRAPTOR_BINARY");
    document.getElementById("veloBrowseApiConfigBtn").onclick = () => {
      openFsBrowseModal(
        "Select Velociraptor API config file",
        apiConfigInput.value.trim(),
        apiConfigInput.id,
      );
    };
    document.getElementById("veloBrowseBinaryBtn").onclick = () => {
      openFsBrowseModal(
        "Select Velociraptor binary",
        binaryInput.value.trim(),
        binaryInput.id,
      );
    };

    const downloadBtn = document.getElementById("veloDownloadLatestBtn");
    const downloadMsg = document.getElementById("veloDownloadMsg");
    downloadBtn.onclick = async () => {
      downloadBtn.disabled = true;
      downloadMsg.textContent = "downloading latest release…";
      try {
        const resp = await fetch("/settings/velociraptor/download-latest", {
          method: "POST",
        });
        const j = await resp.json();
        if (!resp.ok || !j.ok)
          throw new Error(j.error || "HTTP " + resp.status);
        binaryInput.value = j.path;
        downloadMsg.textContent = `downloaded v${j.version} (${j.assetName}) → ${j.path}. Click Save to apply.`;
      } catch (err) {
        downloadMsg.textContent = "download failed: " + err.message;
      } finally {
        downloadBtn.disabled = false;
      }
    };
  }

  window.initFsBrowse = initFsBrowse;
})();
