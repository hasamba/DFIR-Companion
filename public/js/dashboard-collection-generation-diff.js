// Collection generation diff (#1128) — a genuine new top-level section (Codex design-review
// finding M5 on RECOMMENDATION-1128.md: a route with no real consumer risks becoming a third
// unconsumed disclosure surface, matching 932.17's own review of #1108). Renders
// GET /cases/:id/collection-generations/compare — adjacent-pair diffs of #1108's own
// collection-generation ledger (persistence domain).
//
// #1132 extends this SAME panel with a second, INDEPENDENT section for the mobile-app-presence
// domain (GET /cases/:id/mobile-backup-generations/compare) rather than a new top-level dashboard
// section — Codex's own design-review finding on #1132 was explicit that this is the same
// analyst-facing feature ("what changed between two recorded collections") over a second evidence
// type. The persistence and mobile halves keep FULLY SEPARATE loading/ready/unconfigured/error
// state — a failure fetching one must never hide a valid result from the other.
(function () {
  const DIRECTION_LABEL = {
    "present-only-in-earlier": "present only in earlier",
    "present-only-in-later": "present only in later",
    changed: "changed",
  };

  const EXCLUSION_LABEL = {
    partial: "partial coverage",
    filtered: "a filter was applied",
    "ambiguous-identity": "ambiguous identity within its own inventory",
  };

  // esc/escAttr are the GLOBAL, canonical copies from dashboard-escape.js (loaded well before this
  // file, in <head>) — never redeclared here (the drift-test discipline, #387).

  function orderLabel(order) {
    if (!order) return "—";
    return order.kind === "captured" ? esc(String(order.capturedAt)) : `sequence ${esc(String(order.sequence))}`;
  }

  // ── Persistence half (#1128) ────────────────────────────────────────────────────────────────

  let pCohorts = [];
  let pTruncatedCohorts = false;
  let pStatus = "loading"; // "loading" | "ready" | "unconfigured" | "error"
  let pLoadSeq = 0; // generation token: only the latest load may mutate state (case-switch races)

  function persistenceChangeRow(change) {
    const dir = DIRECTION_LABEL[change.direction] || esc(change.direction);
    let key;
    try {
      key = JSON.parse(change.key);
    } catch {
      key = [change.key, ""];
    }
    const [technique, path] = Array.isArray(key) ? key : [String(key), ""];
    const valueText =
      change.direction === "present-only-in-earlier"
        ? `value: ${esc(String(change.earlierValue))}`
        : change.direction === "present-only-in-later"
          ? `value: ${esc(String(change.laterValue))}`
          : `${esc(String(change.earlierValue))} → ${esc(String(change.laterValue))}`;
    return (
      `<tr><td>${esc(dir)}</td><td>${esc(String(technique))}</td><td>${esc(String(path))}</td>` +
      `<td>${valueText}</td></tr>`
    );
  }

  function pairSummary(pair) {
    const count = pair.changes.length;
    return (
      `${orderLabel(pair.earlier.order)} → ${orderLabel(pair.later.order)} — ` +
      `${count} change${count === 1 ? "" : "s"}` +
      (pair.truncated ? " (truncated)" : "") +
      (pair.inventoryTruncated ? " (one side's own inventory was too large to fully compare)" : "") +
      (pair.interveningExcludedCount > 0
        ? `, ${pair.interveningExcludedCount} excluded generation${pair.interveningExcludedCount === 1 ? "" : "s"} in between`
        : "")
    );
  }

  function persistencePairBlock(pair) {
    const rows = pair.changes.map(persistenceChangeRow).join("");
    const table = pair.changes.length
      ? `<table class="cgd-changes"><thead><tr><th>Direction</th><th>Technique</th><th>Path</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="cgd-none">No differences between these two generations.</div>`;
    return `<details class="cgd-pair"><summary>${esc(pairSummary(pair))}</summary>${table}</details>`;
  }

  function excludedBlock(cohort) {
    if (!cohort.excluded.length && !cohort.ambiguousOrder.length) return "";
    const excludedItems = cohort.excluded
      .map((e) => `<li>${esc(e.generationId)} — ${esc(EXCLUSION_LABEL[e.reason] || e.reason)}</li>`)
      .join("");
    const ambiguousItems = cohort.ambiguousOrder
      .map((a) => `<li>${esc(a.generationId)} — shares its order key with another generation; excluded from every pair</li>`)
      .join("");
    return (
      `<details class="cgd-excluded"><summary>${cohort.excluded.length + cohort.ambiguousOrder.length} generation(s) not compared</summary>` +
      `<ul>${excludedItems}${ambiguousItems}</ul></details>`
    );
  }

  function persistenceCohortBlock(cohort) {
    const header = `<div class="cgd-host"><strong>${esc(cohort.resolvedHost)}</strong> — ${esc(String(cohort.eligibleCount))} eligible generation(s)</div>`;
    if (!cohort.pairs.length) {
      return (
        header +
        `<div class="cgd-none">Not enough eligible, same-order-mode generations to compare yet.</div>` +
        excludedBlock(cohort)
      );
    }
    const pairsHtml = cohort.pairs.map(persistencePairBlock).join("");
    const truncatedNote = cohort.truncatedPairs
      ? `<div class="cgd-truncated">Some pairs were omitted — this host has more eligible generations than fit in one response.</div>`
      : "";
    return header + pairsHtml + truncatedNote + excludedBlock(cohort);
  }

  function renderPersistenceSection() {
    if (pStatus === "loading") return `<div class="cgd-none">Loading…</div>`;
    if (pStatus === "error") {
      return `<div class="cgd-error">Could not load the persistence comparison — try again shortly.</div>`;
    }
    if (pStatus === "unconfigured" || !pCohorts.length) {
      return `<div class="cgd-none">No host has two or more eligible, comparable persistence-collection generations yet.</div>`;
    }
    const truncNote = pTruncatedCohorts
      ? `<div class="cgd-truncated">Some hosts were omitted — this case has more compared hosts than fit in one response.</div>`
      : "";
    return pCohorts.map(persistenceCohortBlock).join("") + truncNote;
  }

  async function loadPersistenceDiff(caseId) {
    const seq = ++pLoadSeq;
    pStatus = "loading";
    paintCollectionGenerationDiff();
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/collection-generations/compare`);
      if (seq !== pLoadSeq) return;
      if (r.status === 501) {
        pCohorts = [];
        pTruncatedCohorts = false;
        pStatus = "unconfigured";
        paintCollectionGenerationDiff();
        return;
      }
      if (!r.ok) {
        pStatus = "error";
        paintCollectionGenerationDiff();
        return;
      }
      const body = await r.json();
      if (seq !== pLoadSeq) return;
      pCohorts = Array.isArray(body.cohorts) ? body.cohorts : [];
      pTruncatedCohorts = Boolean(body.truncatedCohorts);
      pStatus = "ready";
      paintCollectionGenerationDiff();
    } catch {
      if (seq !== pLoadSeq) return;
      pStatus = "error";
      paintCollectionGenerationDiff();
    }
  }

  // ── Mobile half (#1132) ─────────────────────────────────────────────────────────────────────

  let mCohorts = [];
  let mTruncatedCohorts = false;
  let mStatus = "loading";
  let mLoadSeq = 0;
  let mCandidates = null; // fetched lazily, only when the recording form is opened
  let mFormOpen = false;

  function mobileChangeRow(change) {
    const dir = DIRECTION_LABEL[change.direction] || esc(change.direction);
    const bundleId = change.key;
    const valueText =
      change.direction === "present-only-in-earlier"
        ? `${esc(change.earlierValue.itemName)} ${esc(change.earlierValue.version)}`
        : change.direction === "present-only-in-later"
          ? `${esc(change.laterValue.itemName)} ${esc(change.laterValue.version)}`
          : `${esc(change.earlierValue.itemName)} ${esc(change.earlierValue.version)} → ${esc(change.laterValue.itemName)} ${esc(change.laterValue.version)}`;
    return `<tr><td>${esc(dir)}</td><td>${esc(bundleId)}</td><td>${valueText}</td></tr>`;
  }

  function mobilePairBlock(pair) {
    const rows = pair.changes.map(mobileChangeRow).join("");
    const table = pair.changes.length
      ? `<table class="cgd-changes"><thead><tr><th>Direction</th><th>Bundle ID</th><th>Item / Version</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="cgd-none">No differences between these two generations.</div>`;
    return `<details class="cgd-pair"><summary>${esc(pairSummary(pair))}</summary>${table}</details>`;
  }

  function mobileCohortBlock(cohort) {
    const deviceLabel = `${cohort.resolvedDevice.kind}: ${cohort.resolvedDevice.value}`;
    const header = `<div class="cgd-host"><strong>${esc(deviceLabel)}</strong> — ${esc(String(cohort.eligibleCount))} eligible generation(s)</div>`;
    if (!cohort.pairs.length) {
      return (
        header +
        `<div class="cgd-none">Not enough eligible, same-order-mode generations to compare yet.</div>` +
        excludedBlock(cohort)
      );
    }
    const pairsHtml = cohort.pairs.map(mobilePairBlock).join("");
    const truncatedNote = cohort.truncatedPairs
      ? `<div class="cgd-truncated">Some pairs were omitted — this device has more eligible generations than fit in one response.</div>`
      : "";
    return header + pairsHtml + truncatedNote + excludedBlock(cohort);
  }

  function candidateOptionsHtml(candidates, kind) {
    return candidates
      .filter((c) => c.looksLike === kind)
      .map((c) => {
        const preview =
          kind === "backup-info"
            ? `${c.preview.deviceIdentity.kind}: ${c.preview.deviceIdentity.value}${c.preview.capturedAt ? `, ${c.preview.capturedAt}` : ", no date"}`
            : `${c.preview.appCount} app(s)`;
        return `<option value="${escAttr(String(c.importSeq))}">#${esc(String(c.importSeq))} ${esc(c.originalName)} (${esc(preview)})</option>`;
      })
      .join("");
  }

  function recordFormHtml() {
    if (!mFormOpen) {
      return `<button type="button" class="cgd-act" data-cgd-action="open-record-form">+ Record a backup pairing…</button>`;
    }
    if (!mCandidates) {
      return `<div class="cgd-none">Loading candidate imports…</div>`;
    }
    const backupOptions = candidateOptionsHtml(mCandidates, "backup-info");
    const appsOptions = candidateOptionsHtml(mCandidates, "installed-apps");
    if (!backupOptions || !appsOptions) {
      return (
        `<div class="cgd-none">No recognized "iTunes Backup Information" and "iTunes Backup - Installed ` +
        `Applications" import pair found among recent imports yet.</div>` +
        `<button type="button" class="cgd-act" data-cgd-action="close-record-form">Cancel</button>`
      );
    }
    return (
      `<div class="cgd-record-form">` +
      `<label>Backup Information import: <select data-cgd-field="backupInfoImportSeq">${backupOptions}</select></label>` +
      `<label>Installed Applications import: <select data-cgd-field="installedAppsImportSeq">${appsOptions}</select></label>` +
      `<label>Completeness: <select data-cgd-field="completenessState">` +
      `<option value="complete">Complete</option><option value="partial">Partial</option><option value="unknown">Unknown</option>` +
      `</select></label>` +
      `<button type="button" class="cgd-act" data-cgd-action="submit-record-form">Record pairing</button> ` +
      `<button type="button" class="cgd-act" data-cgd-action="close-record-form">Cancel</button>` +
      `</div>`
    );
  }

  function renderMobileSection() {
    const form = recordFormHtml();
    if (mStatus === "loading") return `<div class="cgd-none">Loading…</div>` + form;
    if (mStatus === "error") {
      return `<div class="cgd-error">Could not load the mobile backup comparison — try again shortly.</div>` + form;
    }
    if (mStatus === "unconfigured" || !mCohorts.length) {
      return (
        `<div class="cgd-none">No device has two or more eligible, comparable app-presence generations yet.</div>` +
        form
      );
    }
    const truncNote = mTruncatedCohorts
      ? `<div class="cgd-truncated">Some devices were omitted — this case has more compared devices than fit in one response.</div>`
      : "";
    return mCohorts.map(mobileCohortBlock).join("") + truncNote + form;
  }

  async function loadMobileDiff(caseId) {
    const seq = ++mLoadSeq;
    mStatus = "loading";
    paintCollectionGenerationDiff();
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/mobile-backup-generations/compare`);
      if (seq !== mLoadSeq) return;
      if (r.status === 501) {
        mCohorts = [];
        mTruncatedCohorts = false;
        mStatus = "unconfigured";
        paintCollectionGenerationDiff();
        return;
      }
      if (!r.ok) {
        mStatus = "error";
        paintCollectionGenerationDiff();
        return;
      }
      const body = await r.json();
      if (seq !== mLoadSeq) return;
      mCohorts = Array.isArray(body.cohorts) ? body.cohorts : [];
      mTruncatedCohorts = Boolean(body.truncatedCohorts);
      mStatus = "ready";
      paintCollectionGenerationDiff();
    } catch {
      if (seq !== mLoadSeq) return;
      mStatus = "error";
      paintCollectionGenerationDiff();
    }
  }

  async function openRecordForm(caseId) {
    mFormOpen = true;
    mCandidates = null;
    paintCollectionGenerationDiff();
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/mobile-backup-generations/candidate-imports`);
      const body = r.ok ? await r.json() : { candidates: [] };
      mCandidates = Array.isArray(body.candidates) ? body.candidates : [];
    } catch {
      mCandidates = [];
    }
    paintCollectionGenerationDiff();
  }

  function closeRecordForm() {
    mFormOpen = false;
    mCandidates = null;
    paintCollectionGenerationDiff();
  }

  async function submitRecordForm(caseId, el) {
    const backupInfoImportSeq = Number(el.querySelector('[data-cgd-field="backupInfoImportSeq"]').value);
    const installedAppsImportSeq = Number(el.querySelector('[data-cgd-field="installedAppsImportSeq"]').value);
    const completenessState = el.querySelector('[data-cgd-field="completenessState"]').value;
    const confirmed = confirm(
      `Attest that import #${backupInfoImportSeq} (Backup Information) and import #${installedAppsImportSeq} ` +
        `(Installed Applications) come from the SAME physical backup? This is an examiner attestation, ` +
        `not an automatic verification — the two files cannot be proven to share an origin from their content alone.`,
    );
    if (!confirmed) return;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/mobile-backup-generations`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          backupInfoImportSeq,
          installedAppsImportSeq,
          domain: "mobile-app-presence",
          completenessState,
          attestedSameBackup: true,
        }),
      });
      if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        throw new Error(e.error || "HTTP " + r.status);
      }
      closeRecordForm();
      void loadMobileDiff(caseId);
    } catch (err) {
      alert("Could not record this pairing: " + err.message);
    }
  }

  // ── Shared paint + case-connect entry point ────────────────────────────────────────────────

  function renderCollectionGenerationDiff() {
    return (
      `<h3 class="cgd-subheading">Persistence</h3>${renderPersistenceSection()}` +
      `<h3 class="cgd-subheading">Mobile backups</h3>${renderMobileSection()}`
    );
  }

  function paintCollectionGenerationDiff() {
    const el = document.getElementById("collectionGenerationDiffBody");
    if (!el) return;
    el.innerHTML = renderCollectionGenerationDiff();
    if (!el.dataset.cgdBound) {
      el.addEventListener("click", onPanelClick);
      el.dataset.cgdBound = "1";
    }
  }

  function onPanelClick(evt) {
    const target = evt.target && evt.target.closest ? evt.target : null;
    if (!target) return;
    const button = target.closest("[data-cgd-action]");
    if (!button) return;
    const caseId = (document.getElementById("caseId") || {}).value;
    if (!caseId || !caseId.trim()) return;
    const action = button.getAttribute("data-cgd-action");
    if (action === "open-record-form") void openRecordForm(caseId.trim());
    else if (action === "close-record-form") closeRecordForm();
    else if (action === "submit-record-form") {
      const form = button.closest(".cgd-record-form");
      if (form) void submitRecordForm(caseId.trim(), form);
    }
  }

  async function loadCollectionGenerationDiff(caseId) {
    if (!caseId) return;
    mFormOpen = false;
    mCandidates = null;
    // Independent — a failure in one must never hide a valid result from the other. Settled with
    // Promise.all so a caller (a test, or a future progress-reporting caller) can await BOTH
    // finishing; runPanelLoaders itself tracks completion by intercepting fetch() directly and
    // never reads this return value, so returning it changes nothing for the real dashboard.
    await Promise.all([loadPersistenceDiff(caseId), loadMobileDiff(caseId)]);
  }

  globalThis.renderCollectionGenerationDiff = renderCollectionGenerationDiff;
  globalThis.loadCollectionGenerationDiff = loadCollectionGenerationDiff;
})();
