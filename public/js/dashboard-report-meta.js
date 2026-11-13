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
  }

  function fetchReportMeta(caseId) {
    return fetch(`/cases/${caseId}/report-meta`)
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((m) => {
        fillReportMeta(m);
        rmFilledFor = caseId;
      });
  }

  function loadReportMeta(caseId) {
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
  window.saveReportMeta = saveReportMeta;
  window.setReportLogo = setReportLogo;
})();
