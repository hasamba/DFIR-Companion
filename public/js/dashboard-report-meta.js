// Report metadata — the case-details form and its company logo (#415 tier 3) (#415 tier 3).
//
// rmLogo is a base64 data URI held client-side and sent inline with the rest of report-meta; the
// server re-validates it. It and its size cap are private, reached only through setReportLogo().
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  // Company logo is uploaded client-side, held as a base64 data URI, and sent inline with
  // the rest of report-meta (the server re-validates: raster-only, length-capped).
  let rmLogo = ""; // current company-logo data URI, or ""
  const LOGO_MAX_LEN = 1000000; // mirror reportMeta.ts LOGO_MAX_LEN (~1 MB text)
  // The version of the report details this form shows ("" = never saved). Sent with every save so
  // the server refuses one that would overwrite a newer version (e.g. Watson's approved text).
  let rmBaseUpdatedAt = "";
  const STALE_TEXT = "Report details changed since you opened them — reload";
  // The case whose stored details the form holds ("" = never loaded). A save from a form that was
  // never loaded for this case loads them first, so it neither 409s nor wipes the other fields.
  let rmFilledFor = "";
  // The form as last filled from the server: a different reading now means unsaved edits.
  let rmClean = "";
  const formKey = () =>
    Array.from(document.querySelectorAll('#sec-case-details input[id^="rm-"], #sec-case-details textarea[id^="rm-"]'))
      .map((el) => (el.type === "checkbox" ? el.checked : el.value))
      .join("\u0001") + rmLogo;
  function renderLogoPreview() {
    const wrap = document.getElementById("rm-logoPreviewWrap");
    const img = document.getElementById("rm-logoPreview");
    if (rmLogo) {
      img.src = rmLogo;
      wrap.style.display = "flex";
    } else {
      img.removeAttribute("src");
      wrap.style.display = "none";
    }
  }

  function fillReportMeta(m) {
    rmBaseUpdatedAt = m.updatedAt || "";
    const v = (id, val) => (document.getElementById(id).value = val || "");
    v("rm-companyName", m.companyName);
    rmLogo = m.companyLogo || "";
    renderLogoPreview();
    v("rm-organization", m.organization);
    v("rm-incidentId", m.incidentId);
    v("rm-investigators", (m.investigators || []).join("\n"));
    v("rm-reviewer", m.reviewer);
    v("rm-incidentManager", m.incidentManager);
    v("rm-restrictions", m.restrictions);
    document.getElementById("rm-includeDisclaimer").checked =
      m.includeDisclaimer !== false;
    v("rm-intendedAudience", m.intendedAudience);
    v("rm-executiveSummary", m.executiveSummary);
    v("rm-businessImpact", m.businessImpact);
    v("rm-investigationLimitations", m.investigationLimitations);
    v("rm-investigationGoals", m.investigationGoals);
    v("rm-conclusions", m.conclusions);
    v("rm-recommendations", (m.recommendations || []).join("\n"));
    document.getElementById("rm-revisions").value = rowsToText(m.revisions, [
      "version",
      "date",
      "author",
      "comments",
    ]);
    document.getElementById("rm-distribution").value = rowsToText(
      m.distribution,
      ["name", "role", "method"],
    );
    document.getElementById("rm-glossary").value = rowsToText(m.glossary, [
      "term",
      "explanation",
    ]);
    rmClean = formKey();
    if (typeof watsonMarkReportSlots === "function") watsonMarkReportSlots(m); // "Watson" badge on the fields it wrote
  }

  // #2904: is `caseId` still the case on screen? Fails open when there is no #caseId to read.
  function rmOnScreen(caseId) {
    const el = document.getElementById("caseId");
    return !el || typeof el.value !== "string" || el.value.trim() === caseId;
  }
  // #2904: every GET takes a generation, and its answer fills the form only when it is the newest
  // GET and its case is still on screen. A superseded read whose case the newer read already filled
  // resolves (a save may go on); any other stale answer rejects, so no save PUTs a form it did not fill.
  let rmGen = 0;
  const RM_CASE_CHANGED = "the case on screen changed";
  function fetchReportMeta(caseId) {
    const gen = ++rmGen;
    return fetch(`/cases/${caseId}/report-meta`)
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((m) => {
        if (!rmOnScreen(caseId)) throw new Error(RM_CASE_CHANGED);
        if (gen !== rmGen) {
          if (rmFilledFor === caseId) return;
          throw new Error(RM_CASE_CHANGED);
        }
        fillReportMeta(m);
        rmFilledFor = caseId;
      });
  }

  // Watson wrote report text: show it, unless the analyst has unsaved edits in the form (a save would
  // refuse on the newer version anyway, and typing must not be wiped).
  function reloadReportMetaIfClean(caseId) {
    if (rmFilledFor === caseId && formKey() !== rmClean) return Promise.resolve();
    return fetchReportMeta(caseId).catch(() => {});
  }

  // #2904: a load for another case blanks the previous case's details at once — its text must not
  // sit in this case's form, not even when this case's read fails.
  let rmShownFor = "";
  function blankReportMeta(caseId) {
    rmShownFor = caseId;
    rmFilledFor = "";
    fillReportMeta({});
    const st = document.getElementById("rmStatus");
    if (st) st.textContent = ""; // a save of the previous case's form may still say "saving…"
  }
  // #2915: a cancelled or failed case load blanks the form too (and retires any GET on its way); the
  // next open — the same case included — reads the details again.
  function onReportMetaReset(caseId) {
    if (caseId !== null) return;
    rmGen++;
    blankReportMeta("");
  }
  function loadReportMeta(caseId) {
    if (!rmOnScreen(caseId)) return Promise.resolve(); // a late caller for a case the analyst left
    typeof DfirPanelDefer !== "undefined" && typeof DfirPanelDefer.onReset === "function" && DfirPanelDefer.onReset(onReportMetaReset);
    if (rmShownFor !== caseId) blankReportMeta(caseId);
    return fetchReportMeta(caseId).catch(() => {});
  }

  // `edits` ({ "rm-<field>": value }) are applied to the form after it holds this case's details:
  // how another panel (the Executive Summary "Save") changes one field without touching the rest.
  function saveReportMeta(edits) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return Promise.resolve();
    if (rmFilledFor === caseId) return putReportMeta(caseId, edits);
    const st = document.getElementById("rmStatus");
    st.textContent = "loading case details…";
    return fetchReportMeta(caseId)
      .then(() => putReportMeta(caseId, edits))
      .catch((e) => (st.textContent = "save failed: " + e.message));
  }

  function putReportMeta(caseId, edits) {
    for (const [id, value] of Object.entries(edits || {})) {
      const el = document.getElementById(id);
      if (el) el.value = value;
    }
    const g = (id) => document.getElementById(id).value;
    const body = {
      companyName: g("rm-companyName"),
      companyLogo: rmLogo,
      organization: g("rm-organization"),
      incidentId: g("rm-incidentId"),
      investigators: linesToArray(g("rm-investigators")),
      reviewer: g("rm-reviewer"),
      incidentManager: g("rm-incidentManager"),
      restrictions: g("rm-restrictions"),
      includeDisclaimer: document.getElementById("rm-includeDisclaimer")
        .checked,
      intendedAudience: g("rm-intendedAudience"),
      executiveSummary: g("rm-executiveSummary"),
      businessImpact: g("rm-businessImpact"),
      investigationLimitations: g("rm-investigationLimitations"),
      investigationGoals: g("rm-investigationGoals"),
      conclusions: g("rm-conclusions"),
      recommendations: linesToArray(g("rm-recommendations")),
      revisions: parseRows(g("rm-revisions"), [
        "version",
        "date",
        "author",
        "comments",
      ]),
      distribution: parseRows(g("rm-distribution"), ["name", "role", "method"]),
      glossary: parseRows(g("rm-glossary"), ["term", "explanation"]),
      baseUpdatedAt: rmBaseUpdatedAt,
    };
    const st = document.getElementById("rmStatus");
    st.textContent = "saving…";
    return fetch(`/cases/${caseId}/report-meta`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => {
        if (r.status === 409) throw new Error(STALE_TEXT);
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((m) => {
        if (!rmOnScreen(caseId)) return; // #2904: saved, but the analyst is on another case now
        fillReportMeta(m);
        rmFilledFor = caseId;
        st.textContent = "saved ✓";
        setTimeout(() => (st.textContent = ""), 2500);
      })
      .catch((e) => {
        st.textContent =
          e.message === STALE_TEXT
            ? STALE_TEXT
            : "save failed: " +
              e.message +
              " — restart the companion server if this 404s";
      });
  }

  // THE PAGE OWNS THE FILE PICKER, THIS OWNS THE LOGO. The upload handler used to assign rmLogo
  // directly and read LOGO_MAX_LEN to size-check it, which is two pieces of this feature's state
  // living in the page. Publishing the operation instead keeps both private: the caller learns
  // whether the image was accepted and nothing else.
  function setReportLogo(uri) {
    if (uri && uri.length > LOGO_MAX_LEN) return false;
    rmLogo = uri || "";
    renderLogoPreview();
    return true;
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.fillReportMeta = fillReportMeta;
  window.loadReportMeta = loadReportMeta;
  window.reloadReportMetaIfClean = reloadReportMetaIfClean;
  window.saveReportMeta = saveReportMeta;
  window.setReportLogo = setReportLogo;
})();
