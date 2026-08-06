// Import case — a snapshot archive (#56), an encrypted archive, or a case pulled from DFIR-IRIS
// (#415 tier 3).
//
// EVERYTHING IS IN THE INITIALIZER, including two `const`s. `const importCaseOverlay =
// document.getElementById("importCaseOverlay")` reads as module body — it is a VariableStatement —
// and in a <head> script it evaluates to null before the markup exists, so the four statements
// below that use it would throw or silently do nothing. The splitter flags exactly this shape; it
// is why the whole block moves as one initializer rather than being split into body and wiring.
//
// `closeImportCaseModal` is declared here too and used only from inside this block's own handlers,
// so it stays inside the initializer with them rather than being hoisted out and published.
//
// The two guard stanzas that earlier extractions left in this range — for the search/scope wiring
// and for enrichment — did NOT come with it.
(function () {
  function initImportCase() {
    const importCaseOverlay = document.getElementById("importCaseOverlay");
    function closeImportCaseModal() {
      importCaseOverlay.classList.remove("open");
    }
    document.getElementById("importCaseBtn").onclick = () => {
      document.getElementById("importCaseHint").textContent = "";
      importCaseOverlay.classList.add("open");
    };
    document.getElementById("importCaseCancel").onclick = closeImportCaseModal;
    importCaseOverlay.addEventListener("click", (e) => {
      if (e.target === importCaseOverlay) closeImportCaseModal();
    });
    document.getElementById("importCaseEncrypted").onclick = () => {
      closeImportCaseModal();
      document.getElementById("encryptedImportFile").click();
    };
    document.getElementById("importCaseIris").onclick = () => {
      closeImportCaseModal();
      openIrisImportModal();
    };

    let _pendingImportFile = null;
    document.getElementById("encryptedImportFile").onchange = (e) => {
      const file = e.target.files && e.target.files[0];
      e.target.value = ""; // allow re-selecting the same file
      if (!file) return;
      _pendingImportFile = file;
      document.getElementById("ipFilename").textContent = file.name;
      document.getElementById("ipPassword").value = "";
      document.getElementById("ipMsg").textContent = "";
      document.getElementById("importPasswordOverlay").classList.add("open");
      document.getElementById("ipPassword").focus();
    };
    document.getElementById("ipCancel").onclick = () => {
      document.getElementById("importPasswordOverlay").classList.remove("open");
      _pendingImportFile = null;
    };
    document
      .getElementById("importPasswordOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "importPasswordOverlay") {
          e.target.classList.remove("open");
          _pendingImportFile = null;
        }
      });
    document.getElementById("ipImport").onclick = async () => {
      const file = _pendingImportFile;
      const password = document.getElementById("ipPassword").value;
      const msg = document.getElementById("ipMsg");
      if (!file) {
        msg.textContent = "no file selected";
        return;
      }
      if (!password) {
        msg.textContent = "password is required";
        return;
      }
      const LARGE_MB = 180; // base64 body must fit DFIR_MAX_BODY_MB (default 256 MB → ~190 MB raw)
      if (file.size > LARGE_MB * 1024 * 1024) {
        msg.textContent =
          "this .dfircase file is too large to import via the dashboard (over 180 MB) — contact support or split the case";
        return;
      }
      const status = document.getElementById("status");
      const btn = document.getElementById("ipImport");
      const cancelBtn = document.getElementById("ipCancel");
      btn.disabled = true;
      cancelBtn.disabled = true;
      msg.textContent = "reading file…";
      try {
        const arrayBuffer = await file.arrayBuffer();
        const base64 = arrayBufferToBase64(arrayBuffer);
        const importInto = async (targetCaseId) => {
          const body = {
            data: base64,
            password,
            ...(targetCaseId ? { targetCaseId } : {}),
          };
          return fetch("/cases/import/encrypted", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(body),
          });
        };
        msg.textContent = "importing…";
        let res = await importInto(undefined);
        // Resolve id collisions by asking for a new id (up to a few tries), defaulting to "<id>-copy".
        let guard = 0;
        while (res.status === 409 && guard++ < 5) {
          const j = await res.json().catch(() => ({}));
          const suggested = (j.caseId || "imported") + "-copy";
          const newId = window.prompt(
            `A case "${j.caseId || ""}" already exists. Import under a different case id:`,
            suggested,
          );
          if (!newId) {
            msg.textContent = "import cancelled";
            return;
          }
          res = await importInto(newId.trim());
        }
        const body = await res.json().catch(() => ({}));
        if (res.status === 201) {
          const c = body.counts || {};
          document
            .getElementById("importPasswordOverlay")
            .classList.remove("open");
          _pendingImportFile = null;
          status.textContent = `imported case ${body.caseId} (${c.forensicEvents || 0} events, ${c.findings || 0} findings, ${c.iocs || 0} IOCs)`;
          document.getElementById("caseId").value = body.caseId;
          loadCaseList();
          connect(); // attach to the freshly imported case
        } else if (res.status === 400) {
          msg.textContent =
            "import failed: " +
            (body.error || "wrong password or corrupt file");
        } else {
          msg.textContent =
            "import failed: " + (body.error || "HTTP " + res.status);
        }
      } catch (err) {
        msg.textContent =
          "import failed: " + err.message + " — is the companion running?";
      } finally {
        btn.disabled = false;
        cancelBtn.disabled = false;
      }
    };
  }

  window.initImportCase = initImportCase;
})();
