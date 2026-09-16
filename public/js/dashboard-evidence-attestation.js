// Analyst-attested evidence-class coverage (#1111) — a compact addition inside the Hypotheses
// panel, not a new top-level dashboard section (avoids the full section-registration checklist
// for a feature this narrow). Mirrors dashboard-host-scope.js's own generation-token / prompt()
// pattern exactly: an attestation is a signed assertion recorded against the analyst's own name
// and quoted in refutationGate.ts's own disclosure note, so the same care applies.
(function () {
  let attestations = [];
  let loadSeq = 0; // generation token: only the latest load may mutate state (case-switch races)
  let loadCase = null;

  const EVIDENCE_CLASSES = ["execution", "file-activity", "network", "persistence"];
  const CLASS_LABEL = {
    execution: "Execution",
    "file-activity": "File activity",
    network: "Network",
    persistence: "Persistence",
  };

  // esc/escAttr are the GLOBAL, canonical copies from dashboard-escape.js (loaded well before this
  // file, in <head>) — never redeclared here. Two implementations of an XSS-critical primitive is
  // a real hazard (#387); dashboard-escape.js's own drift test enforces exactly three copies stay
  // byte-identical, and a fourth, unmonitored one is exactly the mistake that guards against.

  function activeFor(cls) {
    // Only the LATEST entry per class matters — mirrors evidenceAttestationStore.ts's own rule
    // exactly, so this panel never disagrees with what refutationGate.ts actually consumes.
    let latest = null;
    for (const a of attestations) if (a.evidenceClass === cls) latest = a;
    return latest && !latest.revokedAt ? latest : null;
  }

  function rowFor(cls) {
    const active = activeFor(cls);
    const name = escAttr(cls);
    if (active) {
      return (
        `<div class="ea-row ea-active" data-ea-class="${name}">` +
        `<span class="ea-label">${esc(CLASS_LABEL[cls])}</span>` +
        `<span class="ea-status">Attested by ${esc(active.confirmedBy)} on ` +
        `${esc(String(active.confirmedAt).slice(0, 10))}: ${esc(active.reason)}</span>` +
        `<button type="button" class="ea-act" data-ea-action="revoke" data-ea-class="${name}">Revoke</button>` +
        `</div>`
      );
    }
    return (
      `<div class="ea-row" data-ea-class="${name}">` +
      `<span class="ea-label">${esc(CLASS_LABEL[cls])}</span>` +
      `<span class="ea-status ea-none">Not attested</span>` +
      `<button type="button" class="ea-act" data-ea-action="attest" data-ea-class="${name}">Attest…</button>` +
      `</div>`
    );
  }

  // Pure: the whole mini-panel as a string, testable without a DOM.
  function renderEvidenceAttestations() {
    return (
      `<div class="ea-help">Confirm evidence CAPABLE OF SETTLING an absence claim was fully ` +
      `examined for this case — a signed assertion, recorded against your name, that ` +
      `refutationGate.ts trusts alongside automatically detected coverage. Required for a ` +
      `refutation the timeline's own sources cannot otherwise support.</div>` +
      EVIDENCE_CLASSES.map(rowFor).join("")
    );
  }

  function paintEvidenceAttestations() {
    const el = document.getElementById("hypCoverageAttest");
    if (!el) return;
    el.innerHTML = renderEvidenceAttestations();
    if (!el.dataset.eaBound) {
      el.addEventListener("click", onPanelClick);
      el.dataset.eaBound = "1";
    }
  }

  async function loadEvidenceAttestations(caseId) {
    if (!caseId) return;
    const seq = ++loadSeq;
    loadCase = caseId;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/evidence-attestations`);
      if (!r.ok) {
        if (seq !== loadSeq) return; // superseded by a newer load — ignore entirely
        attestations = [];
        // 501 means the store is not configured — an empty panel is the honest rendering.
        paintEvidenceAttestations();
        return;
      }
      const body = await r.json();
      if (seq !== loadSeq) return; // a stale success must not overwrite the newer case
      attestations = Array.isArray(body.attestations) ? body.attestations : [];
      paintEvidenceAttestations();
    } catch {
      if (seq !== loadSeq) return;
      attestations = [];
      paintEvidenceAttestations();
    }
  }

  async function attestEvidenceClass(caseId, cls, reason) {
    const seq = loadSeq;
    const r = await fetch(
      `/cases/${encodeURIComponent(caseId)}/evidence-attestations/${encodeURIComponent(cls)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason }),
      },
    );
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      throw new Error(e.error || "HTTP " + r.status);
    }
    const body = await r.json();
    if (seq === loadSeq) {
      attestations = Array.isArray(body.attestations) ? body.attestations : [];
      paintEvidenceAttestations();
    } else if (loadCase === caseId) {
      void loadEvidenceAttestations(caseId);
    }
  }

  async function revokeEvidenceClass(caseId, cls) {
    const seq = loadSeq;
    const r = await fetch(
      `/cases/${encodeURIComponent(caseId)}/evidence-attestations/${encodeURIComponent(cls)}`,
      { method: "DELETE" },
    );
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      throw new Error(e.error || "HTTP " + r.status);
    }
    const body = await r.json();
    if (seq === loadSeq) {
      attestations = Array.isArray(body.attestations) ? body.attestations : [];
      paintEvidenceAttestations();
    } else if (loadCase === caseId) {
      void loadEvidenceAttestations(caseId);
    }
  }

  // ONE delegated listener on the mini-panel, bound once — the innerHTML is replaced on every
  // repaint, so per-button listeners would be lost each time (same convention as host-scope's own
  // onPanelClick).
  function onPanelClick(evt) {
    const target = evt.target && evt.target.closest ? evt.target : null;
    if (!target) return;
    const button = target.closest("[data-ea-action]");
    if (!button) return;
    const cls = button.getAttribute("data-ea-class");
    const action = button.getAttribute("data-ea-action");
    if (!cls || !action) return;

    const caseId = (document.getElementById("caseId") || {}).value;
    if (!caseId || !caseId.trim()) return;

    if (action === "attest") {
      const asked = prompt(
        `Attest ${CLASS_LABEL[cls] || cls} coverage for this case? State what you reviewed — ` +
          `this is recorded against your name and cited whenever a refutation relies on it.`,
        "",
      );
      if (asked === null || !asked.trim()) return; // cancelled, or the server would reject it anyway
      void attestEvidenceClass(caseId.trim(), cls, asked.trim()).catch((err) => {
        alert("Could not record attestation for " + cls + ": " + err.message);
      });
      return;
    }
    if (action === "revoke") {
      void revokeEvidenceClass(caseId.trim(), cls).catch((err) => {
        alert("Could not revoke attestation for " + cls + ": " + err.message);
      });
    }
  }

  globalThis.renderEvidenceAttestations = renderEvidenceAttestations;
  globalThis.loadEvidenceAttestations = loadEvidenceAttestations;
  globalThis.attestEvidenceClass = attestEvidenceClass;
  globalThis.revokeEvidenceClass = revokeEvidenceClass;
})();
