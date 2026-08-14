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
    populateTemplateSelect(); // async, fills while user edits fields
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
  function closeNewCase() {
    document.getElementById("newCaseOverlay").classList.remove("open");
  }
  async function createNewCase() {
    const caseId = document.getElementById("ncCaseId").value.trim();
    const name = document.getElementById("ncName").value.trim();
    const investigator = document.getElementById("ncInvestigator").value.trim();
    const picked = selectedNewCasePlaybook();
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
        }),
      });
      if (res.status === 201) {
        closeNewCase();
        document.getElementById("caseId").value = caseId;
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
        document.getElementById("caseId").value = caseId;
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
