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
  // The one thing in this file that is NOT DOM wiring, and so the one thing that lives in the
  // module body rather than inside the initializer: it reads no element, so the reason the rest of
  // the file has to wait does not apply to it.
  //
  // #672. A .dfircase written by 0.31.0-0.33.0 used the weaker v1 key derivation (scrypt N=2^14),
  // and importing one used to say nothing about that. The import response now carries the
  // archive's container version alongside the version this build writes, and this turns that pair
  // into the sentence the analyst reads.
  //
  // It compares the two NUMBERS the server sent rather than testing `formatVersion < 2`. A
  // hardcoded 2 would silently stop warning about v2 archives the day a v3 lands — the failure
  // would be a warning that no longer appears, which nothing notices.
  //
  // Silence is the answer for every case it cannot judge: equal versions, an archive somehow
  // NEWER than this build (where "your encryption is weak" would be backwards), and either field
  // absent or non-numeric, which means an older companion answered rather than a weak archive.
  function encryptionUpgradeNotice(formatVersion, currentFormatVersion) {
    if (typeof formatVersion !== "number" || typeof currentFormatVersion !== "number") return "";
    if (!(formatVersion < currentFormatVersion)) return "";
    return (
      "Imported, but this archive was encrypted with an older, weaker key derivation. " +
      "Export the case again to upgrade the encryption."
    );
  }

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
      // Undo what a warning from the PREVIOUS import left behind (below).
      document.getElementById("ipImport").hidden = false;
      document.getElementById("ipCancel").textContent = "Cancel";
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
          _pendingImportFile = null;
          // WHERE the warning goes is the whole point, and #status is the one place it cannot go.
          // connect() below opens a WebSocket whose onopen handler in js/dashboard-case-connect.js
          // writes "connected (live)" into #status a few milliseconds later, so a security warning
          // parked there flashes and is gone — possibly without ever painting. The same is true of
          // showToast, which writes #status too and then fades itself after six seconds.
          //
          // So the modal the analyst is already looking at stays OPEN and carries the sentence,
          // and the only control left is the one that closes it. Nothing else on the page writes
          // to ipMsg, and dismissing it is a deliberate act rather than a race with the socket.
          const upgrade = encryptionUpgradeNotice(body.formatVersion, body.currentFormatVersion);
          if (upgrade) {
            msg.textContent = upgrade;
            document.getElementById("ipImport").hidden = true;
            // The import already happened and cannot be undone, so "Cancel" would be a lie.
            cancelBtn.textContent = "Close";
          } else {
            msg.textContent = "";
            document.getElementById("importPasswordOverlay").classList.remove("open");
          }
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

  window.encryptionUpgradeNotice = encryptionUpgradeNotice;
  window.initImportCase = initImportCase;
})();
